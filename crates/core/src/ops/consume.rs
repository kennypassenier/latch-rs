//! L3 consumption & diagnosis: W6 run, S3 history/rollback, S6 verify,
//! W8 state, W9 reset. All read paths run happily on the cached clone
//! (S5) — the network is a freshness bonus, never a requirement.

use crate::config::Config;
use crate::credentials::{CredStore, Source};
use crate::envelope;
use crate::error::LatchError;
use crate::keys;
use crate::lock;
use crate::platform::Platform;
use crate::repo::Repo;

use super::sync::project_for;

/// Build the repo handle from config + stored PAT — shared by every verb
/// and by the UI shell (G1: shells never re-implement this).
pub fn repo_handle<'a>(p: &'a Platform<'a>) -> Result<Repo<'a>, LatchError> {
    let config = Config::load(p)?;
    let repo_name = config.repo.ok_or_else(|| {
        LatchError::other(
            "no secrets repository configured",
            "run 'latch login' first",
        )
    })?;
    let store = CredStore::new(p);
    let pat = store
        .get("pat")?
        .map(|(v, _)| String::from_utf8_lossy(&v).to_string());
    Ok(Repo::new(p, &repo_name, pat))
}

// ── W6 · latch run ──────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RunOutcome {
    pub exit_code: i32,
    pub injected: usize,
    pub stale: bool,
}

/// Decrypt the project's env straight from the clone into a child
/// process's environment — nothing ever touches disk. The clone is
/// refreshed best-effort; offline runs on the cache with a stale notice.
pub fn run(
    p: &Platform,
    cwd: &str,
    env_name: &str,
    program: &str,
    args: &[&str],
) -> Result<RunOutcome, LatchError> {
    crate::discovery::validate_env(env_name)?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let refreshed = repo.refresh(false)?;

    let store = CredStore::new(p);
    let key = keys::for_env(&store, &proj.name, env_name)?.ok_or_else(|| {
        LatchError::other(
            format!(
                "no key for project '{}' ({}) on this machine",
                proj.name, env_name
            ),
            "clone your credentials here (latch clone) or restore a backup (latch key restore)",
        )
    })?;

    let prefix = format!("{}/{}", proj.name, env_name);
    let mut vars: Vec<(String, String)> = Vec::new();
    for enc_name in repo.list(&prefix)? {
        let Some(_flat) = enc_name.strip_suffix(".enc") else {
            continue;
        };
        let Some(sealed) = repo.read(&format!("{}/{}", prefix, enc_name))? else {
            continue; // removed underneath us (concurrent reset) — skip
        };
        let plain = envelope::open(&key.key, &key.id, &sealed, &enc_name)?;
        // W12: group members resolve to the group's stored content.
        let plain = match crate::groups::parse_member(&plain) {
            Some((gname, _)) => crate::groups::group_body(p, &repo, env_name, &gname)?,
            None => plain,
        };
        let text = String::from_utf8(plain).map_err(|_| LatchError::Format {
            context: enc_name.clone(),
            detail: "decrypted content is not utf-8".into(),
        })?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                vars.push((k.trim().to_string(), v.to_string()));
            }
        }
    }
    if vars.is_empty() {
        return Err(LatchError::other(
            format!("no secrets found for {}/{}", proj.name, env_name),
            "commit+push env files first, or check --env",
        ));
    }

    // W7/AR13: expand ${VAR} references at use time, strictly.
    let map: std::collections::BTreeMap<String, String> = vars.iter().cloned().collect();
    let expanded = crate::template::expand_all(&map)?;
    let vars: Vec<(String, String)> = expanded.into_iter().collect();

    let env_refs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let exit_code = p.proc.exec_interactive(program, args, &env_refs)?;
    Ok(RunOutcome {
        exit_code,
        injected: vars.len(),
        stale: !refreshed.is_current(),
    })
}

// ── S3 · history + rollback ─────────────────────────────────────────────

#[derive(Debug)]
pub struct HistoryEntry {
    pub reference: String,
    pub time_unix: u64,
    pub message: String,
}

pub fn history(p: &Platform, cwd: &str) -> Result<Vec<HistoryEntry>, LatchError> {
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let _ = repo.refresh(false)?;
    let out = repo.git_log(&format!("{}/", proj.name))?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, '|');
            Some(HistoryEntry {
                reference: parts.next()?.to_string(),
                time_unix: parts.next()?.parse().ok()?,
                message: parts.next().unwrap_or("").to_string(),
            })
        })
        .collect())
}

/// Restore the project (one env) to `reference` in the clone; the caller
/// then pushes to publish and pulls to apply locally — explicit steps,
/// nothing silent.
pub fn rollback(
    p: &Platform,
    cwd: &str,
    env_name: &str,
    reference: &str,
) -> Result<(), LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    repo.checkout_path(reference, &format!("{}/{}", proj.name, env_name))
}

// ── S6 · verify ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyState {
    Ok,
    Corrupt,
    /// We hold no key for this label/generation.
    NoKey {
        needed: String,
        generation: u16,
    },
    /// Not a latch envelope / future format.
    BadFormat(String),
}

#[derive(Debug)]
pub struct VerifyOutcome {
    pub entries: Vec<(String, VerifyState)>,
    pub stale: bool,
}

/// Authenticate every ciphertext in the repo (or one project) without
/// writing anything.
pub fn verify(p: &Platform, project: Option<&str>) -> Result<VerifyOutcome, LatchError> {
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let refreshed = repo.refresh(false)?;
    let store = CredStore::new(p);

    let mut entries = Vec::new();
    for rel in repo.list("")? {
        if !rel.ends_with(".enc") {
            continue;
        }
        if let Some(pr) = project {
            if !rel.starts_with(&format!("{}/", pr)) {
                continue;
            }
        }
        let Some(sealed) = repo.read(&rel)? else {
            continue; // removed between list and read — skip
        };
        let state = match envelope::peek_key_id(&sealed, &rel) {
            Err(LatchError::Format { detail, .. }) => VerifyState::BadFormat(detail),
            Err(_) => VerifyState::BadFormat("unreadable header".into()),
            Ok(id) => {
                // Which key would open this? Project keys are labeled by
                // project (possibly with .env suffix); group keys as
                // group:<name>.
                let slot = if id.label.starts_with("group:") {
                    id.label.clone()
                } else {
                    format!("key:{}", id.label)
                };
                match store.get(&slot)? {
                    None => VerifyState::NoKey {
                        needed: id.label,
                        generation: id.generation,
                    },
                    Some((raw, _)) => {
                        let decoded = decode_key(&raw);
                        match decoded {
                            Some((generation, key)) if generation == id.generation => {
                                match envelope::open(&key, &id, &sealed, &rel) {
                                    Ok(_) => VerifyState::Ok,
                                    Err(_) => VerifyState::Corrupt,
                                }
                            }
                            _ => VerifyState::NoKey {
                                needed: id.label,
                                generation: id.generation,
                            },
                        }
                    }
                }
            }
        };
        entries.push((rel, state));
    }
    Ok(VerifyOutcome {
        entries,
        stale: !refreshed.is_current(),
    })
}

fn decode_key(raw: &[u8]) -> Option<(u16, [u8; envelope::KEY_LEN])> {
    if raw.len() != 2 + envelope::KEY_LEN {
        return None;
    }
    let generation = u16::from_le_bytes([raw[0], raw[1]]);
    let mut key = [0u8; envelope::KEY_LEN];
    key.copy_from_slice(&raw[2..]);
    Some((generation, key))
}

// ── W8 · state (the doctor) ─────────────────────────────────────────────

#[derive(Debug)]
pub struct ProjectState {
    pub name: String,
    pub dir: String,
    pub dir_exists: bool,
    pub key: Option<(Source, u16)>,
}

#[derive(Debug)]
pub struct StateReport {
    pub latch_home: String,
    pub repo: Option<String>,
    pub pat: Option<Source>,
    pub keyring_available: bool,
    pub cred_file: bool,
    pub clone_exists: bool,
    pub projects: Vec<ProjectState>,
}

pub fn state(p: &Platform) -> Result<StateReport, LatchError> {
    let config = Config::load(p)?;
    let store = CredStore::new(p);
    let pat = store.get("pat")?.map(|(_, s)| s);
    let clone_exists = p
        .files
        .read(&format!("{}/repo/.git/HEAD", p.latch_home))?
        .is_some();
    let mut projects = Vec::new();
    for proj in &config.projects {
        let key = store
            .get(&format!("key:{}", proj.name))?
            .and_then(|(raw, src)| decode_key(&raw).map(|(generation, _)| (src, generation)));
        projects.push(ProjectState {
            name: proj.name.clone(),
            dir: proj.dir.clone(),
            dir_exists: !p.files.walk(&proj.dir)?.is_empty()
                || p.files.read(&format!("{}/.env", proj.dir))?.is_some(),
            key,
        });
    }
    Ok(StateReport {
        latch_home: p.latch_home.clone(),
        repo: config.repo,
        pat,
        keyring_available: p.keyring.available(),
        cred_file: store.file_exists()?,
        clone_exists,
        projects,
    })
}

// ── W9 · reset ──────────────────────────────────────────────────────────

/// Wipe the local clone + session cache. Credentials and config stay; the
/// next command re-clones. The "start over" button.
pub fn reset(p: &Platform, confirmed: bool) -> Result<(), LatchError> {
    if !confirmed {
        let ok = p
            .prompt
            .confirm("wipe the local clone and session cache? (credentials and config stay)")?;
        if !ok {
            return Err(LatchError::other("reset cancelled", "nothing was changed"));
        }
    }
    let _lock = lock::acquire(p, 10, || {})?;
    p.files.remove_tree(&format!("{}/repo", p.latch_home))?;
    if let Some(rt) = &p.runtime_dir {
        p.files.remove(&format!("{}/session.key", rt))?;
    }
    Ok(())
}
