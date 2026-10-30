//! Migration safety net for the master-passphrase login (2026-10-30,
//! Kenny: "feilloos, het mag NIET dat er iets verloren gaat"). Three
//! small tools, no policy of their own:
//!
//! * [`inspect`]: decrypt every ciphertext in the secrets clone through a
//!   given key source and report, per file, the sha256 of the plaintext
//!   or why it did not open. Read-only.
//! * [`take_snapshot`] / [`restore_snapshot`]: copy the machine's
//!   credential files aside before the first write, and put them back if
//!   anything fails.
//! * [`compare`]: the proof. Every file that opened through the old
//!   source must open through the new one to byte-identical plaintext.

use std::collections::{BTreeMap, BTreeSet};

use crate::credentials::{decode_env_value, env_var_for_slot, CredStore};
use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::platform::Platform;
use crate::repo::Repo;

/// Files in the latch home that a migration may touch. The clone
/// (`repo/`) is deliberately absent: it is rebuilt from the remote.
const TRACKED: [&str; 7] = [
    "credentials.enc",
    "credentials.key",
    "credentials.enc.bak",
    "latch.env",
    "latch.env.bak",
    "config.toml",
    "groups.json",
];

pub const SNAPSHOT_DIR: &str = "migration-snapshots";

// ── inspect ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileResult {
    /// Opened; sha256 of the plaintext.
    Opened(String),
    /// The key this file needs is not held (slot name).
    NoKey(String),
    /// A key was held but the file did not open with it, or was unreadable.
    Failed(String),
    /// Not a v2 envelope at all (a v1 leftover). v2 never read it, so it
    /// is neither a regression nor something migration touches.
    NotV2(String),
}

#[derive(Debug, Default)]
pub struct Inspection {
    pub files: BTreeMap<String, FileResult>,
}

impl Inspection {
    pub fn opened(&self) -> usize {
        self.files
            .values()
            .filter(|r| matches!(r, FileResult::Opened(_)))
            .count()
    }

    /// Slots some file needs but the key source does not hold.
    pub fn missing_slots(&self) -> BTreeSet<String> {
        self.files
            .values()
            .filter_map(|r| match r {
                FileResult::NoKey(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    /// Files that are not v2 envelopes, reported and left untouched.
    pub fn not_v2(&self) -> Vec<String> {
        self.files
            .iter()
            .filter(|(_, r)| matches!(r, FileResult::NotV2(_)))
            .map(|(f, _)| f.clone())
            .collect()
    }

    pub fn failures(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .filter_map(|(f, r)| match r {
                FileResult::Failed(why) => Some((f.clone(), why.clone())),
                _ => None,
            })
            .collect()
    }

    /// (opened, total) per top-level folder: a project name or `_groups`.
    pub fn per_project(&self) -> BTreeMap<String, (usize, usize)> {
        let mut out: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (file, r) in &self.files {
            let top = file.split('/').next().unwrap_or("").to_string();
            let e = out.entry(top).or_default();
            if matches!(r, FileResult::NotV2(_)) {
                continue;
            }
            e.1 += 1;
            if matches!(r, FileResult::Opened(_)) {
                e.0 += 1;
            }
        }
        out
    }
}

/// Where inspect looks keys up: slot name in, raw slot value out.
pub type KeySource<'a> = dyn Fn(&str) -> Result<Option<Vec<u8>>, LatchError> + 'a;

/// The ordinary resolution chain (env var, env file, credentials file, keyring).
pub fn chain_source<'a>(
    store: &'a CredStore<'a>,
) -> impl Fn(&str) -> Result<Option<Vec<u8>>, LatchError> + 'a {
    move |slot| Ok(store.get(slot)?.map(|(v, _)| v))
}

/// ONLY the machine's env file: proves the new store works on its own.
pub fn env_file_source<'a>(
    p: &'a Platform<'a>,
) -> impl Fn(&str) -> Result<Option<Vec<u8>>, LatchError> + 'a {
    move |slot| {
        let var = env_var_for_slot(slot);
        match crate::envfile::lookup(p, &var)? {
            Some(v) => Ok(Some(decode_env_value(slot, &var, v)?)),
            None => Ok(None),
        }
    }
}

pub fn inspect(repo: &Repo, source: &KeySource) -> Result<Inspection, LatchError> {
    let mut out = Inspection::default();
    for rel in repo.list("")? {
        if !rel.ends_with(".enc") || rel.starts_with("_escrow/") || rel.starts_with("_keywrap/") {
            continue;
        }
        let result = match repo.read(&rel)? {
            None => FileResult::Failed("unreadable".into()),
            Some(sealed) => open_one(&rel, &sealed, source)?,
        };
        out.files.insert(rel, result);
    }
    Ok(out)
}

fn open_one(rel: &str, sealed: &[u8], source: &KeySource) -> Result<FileResult, LatchError> {
    let id = match envelope::peek_key_id(sealed, rel) {
        Ok(id) => id,
        Err(e @ LatchError::Format { .. }) => return Ok(FileResult::NotV2(e.to_string())),
        Err(e) => return Ok(FileResult::Failed(e.to_string())),
    };
    let slot = if id.label.starts_with("group:") {
        id.label.clone()
    } else {
        format!("key:{}", id.label)
    };
    let Some(raw) = source(&slot)? else {
        return Ok(FileResult::NoKey(slot));
    };
    if raw.len() != 2 + KEY_LEN {
        return Ok(FileResult::Failed(format!(
            "{} has an unexpected length",
            slot
        )));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw[2..]);
    let expected = KeyId::new(id.label.clone(), id.generation)?;
    match envelope::open(&key, &expected, sealed, rel) {
        Ok(plain) => Ok(FileResult::Opened(crate::escrow::fingerprint(&plain))),
        Err(e) => Ok(FileResult::Failed(e.to_string())),
    }
}

/// The proof. `allowed_missing` names slots whose files may stay closed
/// (the user passed --allow-missing, or no source ever held them).
/// Returns one line per violation; empty means proven.
pub fn compare(
    before: &Inspection,
    after: &Inspection,
    allowed_missing: &BTreeSet<String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (file, now) in &after.files {
        let was = before.files.get(file);
        match (was, now) {
            (Some(FileResult::Opened(a)), FileResult::Opened(b)) if a != b => {
                problems.push(format!(
                    "{}: plaintext differs between the old and the new store",
                    file
                ))
            }
            (Some(FileResult::Opened(_)), FileResult::NoKey(s)) => {
                problems.push(format!("{}: opened before, key {} is missing now", file, s))
            }
            (_, FileResult::Failed(why)) => problems.push(format!("{}: {}", file, why)),
            (_, FileResult::NoKey(s)) if !allowed_missing.contains(s) => {
                problems.push(format!("{}: key {} is not held", file, s))
            }
            _ => {}
        }
    }
    for file in before.files.keys() {
        if !after.files.contains_key(file) {
            problems.push(format!(
                "{}: vanished from the clone during migration",
                file
            ));
        }
    }
    problems
}

// ── snapshot ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub dir: String,
    /// Tracked files that existed (and were copied).
    pub present: Vec<String>,
}

/// Copy every tracked file aside, byte for byte. Runs before the first
/// write; the directory is never deleted by latch.
pub fn take_snapshot(p: &Platform) -> Result<Snapshot, LatchError> {
    let dir = format!("{}/{}/{}", p.latch_home, SNAPSHOT_DIR, p.clock.now_unix());
    let mut present = Vec::new();
    for name in TRACKED {
        if let Some(bytes) = p.files.read(&format!("{}/{}", p.latch_home, name))? {
            p.files.write_atomic(&format!("{}/{}", dir, name), &bytes)?;
            present.push(name.to_string());
        }
    }
    Ok(Snapshot { dir, present })
}

/// Put the machine back exactly as the snapshot saw it: copied files are
/// restored, tracked files that did not exist then are removed.
pub fn restore_snapshot(p: &Platform, snap: &Snapshot) -> Result<(), LatchError> {
    for name in TRACKED {
        let live = format!("{}/{}", p.latch_home, name);
        if snap.present.iter().any(|n| n == name) {
            let bytes = p
                .files
                .read(&format!("{}/{}", snap.dir, name))?
                .ok_or_else(|| {
                    LatchError::other(
                        format!("snapshot file {} is missing", name),
                        format!("copy it back by hand from {}", snap.dir),
                    )
                })?;
            p.files.write_atomic(&live, &bytes)?;
        } else {
            p.files.remove(&live)?;
        }
    }
    Ok(())
}
