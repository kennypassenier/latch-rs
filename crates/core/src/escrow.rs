//! D13 · escrow awareness (mini-round 2026-09-02, after a keyring wipe took
//! every key on the machine). A keyring protects against being READ, not
//! against being LOST — and latch had no concept of a second copy at all:
//! it could not wait for one, could not check one, and reported a state
//! that looked like a defect while nothing was wrong.
//!
//! What this module adds is deliberately small: a RECORD, in the secrets
//! repository, that an escrow was taken — generation, timestamp and the
//! escrow file's fingerprint. Never key material, never the passphrase.
//! The record lives in the repo because the repo is the one durable thing
//! latch always has: it survives the machine that made it, which is
//! exactly the failure being guarded against.
//!
//! What it deliberately cannot do: prove that the escrow FILE still
//! exists or still opens. `latch state` re-checks the fingerprint when the
//! file is still at its recorded path, and says plainly when it cannot
//! look. A guarantee latch cannot keep is worse than an honest report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::LatchError;
use crate::repo::Repo;

/// Reserved repo area, alongside `_groups` (W12).
pub const ESCROW_PREFIX: &str = "_escrow";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowRecord {
    /// When the escrow was written, unix seconds.
    pub taken_at: u64,
    /// sha256 of the escrow FILE. It is ciphertext, so the digest leaks
    /// nothing; it lets `latch state` tell "the file at that path is the
    /// one that was escrowed" from "something else lives there now".
    pub file_sha256: String,
    /// Where it was written, as a hint for a human. A hint, not a
    /// promise: the whole point of an escrow is that it also lives
    /// somewhere this machine cannot see.
    pub path_hint: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectEscrow {
    /// Key generation (as a string key, so the JSON stays readable) →
    /// what is known about its escrow.
    #[serde(default)]
    pub generations: BTreeMap<String, EscrowRecord>,
    /// Generations published WITHOUT an escrow, on purpose (`--no-escrow`)
    /// → when that was decided. The agreed fallback: an exception may be
    /// made, it may not become invisible. `latch state` keeps showing it
    /// until a real escrow covers that generation.
    #[serde(default)]
    pub skipped: BTreeMap<String, u64>,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn record_path(project: &str) -> String {
    format!("{}/{}.json", ESCROW_PREFIX, project)
}

/// Everything the repo knows about one project's escrows. A missing or
/// unparsable record reads as "nothing known" rather than an error: this
/// must never be the thing that stops someone from reaching their
/// secrets during a recovery.
pub fn read(repo: &Repo, project: &str) -> Result<ProjectEscrow, LatchError> {
    let Some(raw) = repo.read(&record_path(project))? else {
        return Ok(ProjectEscrow::default());
    };
    Ok(serde_json::from_slice(&raw).unwrap_or_default())
}

/// Is there a recorded escrow for exactly this key generation? A newer
/// generation is not covered by an older escrow — that is the whole
/// reason the generation is part of the record (K3 rotation mints a new
/// generation, and the old escrow cannot open what the new key seals).
pub fn has(repo: &Repo, project: &str, generation: u16) -> Result<bool, LatchError> {
    Ok(read(repo, project)?
        .generations
        .contains_key(&generation.to_string()))
}

/// Note that an escrow covering `generation` was taken. Writes into the
/// clone; the caller decides when to push (backup pushes best-effort, so
/// an offline machine still records locally and publishes on its next
/// push rather than failing the backup it was asked to make).
pub fn note(
    repo: &Repo,
    project: &str,
    generation: u16,
    file_sha256: &str,
    path_hint: &str,
    taken_at: u64,
) -> Result<(), LatchError> {
    let mut current = read(repo, project)?;
    current.generations.insert(
        generation.to_string(),
        EscrowRecord {
            taken_at,
            file_sha256: file_sha256.to_string(),
            path_hint: path_hint.to_string(),
        },
    );
    let body = serde_json::to_vec_pretty(&current).expect("escrow record serializes");
    repo.write(&record_path(project), &body)
}

/// The newest recorded escrow for a project, for reporting (W8 state).
pub fn latest(repo: &Repo, project: &str) -> Result<Option<(u16, EscrowRecord)>, LatchError> {
    let all = read(repo, project)?;
    Ok(all
        .generations
        .into_iter()
        .filter_map(|(g, r)| g.parse::<u16>().ok().map(|g| (g, r)))
        .max_by_key(|(g, _)| *g))
}

/// Record that a generation was published deliberately without an
/// escrow. Not an error path — a decision that stays visible.
pub fn note_skipped(
    repo: &Repo,
    project: &str,
    generation: u16,
    at: u64,
) -> Result<(), LatchError> {
    let mut current = read(repo, project)?;
    current.skipped.insert(generation.to_string(), at);
    let body = serde_json::to_vec_pretty(&current).expect("escrow record serializes");
    repo.write(&record_path(project), &body)
}

/// What `latch state` reports per project key (W8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// The escrow file is still at its recorded path and still matches.
    Matches,
    /// Something else lives at that path now — the escrow may still exist
    /// elsewhere, but THIS is not it.
    Differs,
    /// Nothing at the recorded path. Expected when the escrow was moved
    /// off this machine on purpose, which is the point of an escrow.
    Absent,
}

#[derive(Debug, Clone)]
pub enum EscrowStatus {
    Recorded {
        generation: u16,
        taken_at: u64,
        path_hint: String,
        file: FileState,
    },
    SkippedOnPurpose {
        generation: u16,
        at: u64,
    },
    None,
}

/// The escrow story for one key label, including whether the file named
/// in the record is still where it was. Reading the local file is
/// best-effort: an unreadable path reports Absent rather than failing,
/// because state is the command people run WHEN something is wrong.
pub fn status(
    p: &crate::platform::Platform,
    repo: &Repo,
    label: &str,
    generation: u16,
) -> Result<EscrowStatus, LatchError> {
    let all = read(repo, label)?;
    if let Some(rec) = all.generations.get(&generation.to_string()) {
        let file = match p.files.read(&rec.path_hint) {
            Ok(Some(bytes)) if fingerprint(&bytes) == rec.file_sha256 => FileState::Matches,
            Ok(Some(_)) => FileState::Differs,
            _ => FileState::Absent,
        };
        return Ok(EscrowStatus::Recorded {
            generation,
            taken_at: rec.taken_at,
            path_hint: rec.path_hint.clone(),
            file,
        });
    }
    if let Some(at) = all.skipped.get(&generation.to_string()) {
        return Ok(EscrowStatus::SkippedOnPurpose {
            generation,
            at: *at,
        });
    }
    Ok(EscrowStatus::None)
}
