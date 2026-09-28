//! feat-put-1 · replace ONE file of ONE environment and publish it.
//!
//! Asked for by the homelab dashboard (Kenny, 2026-09-28: "latch krijgt
//! een commando voor één bestand"). `latch commit` works on a whole
//! project directory: every ciphertext in the clone without a local file
//! is recorded as removed, and it only refuses when ALL of them would go.
//! A caller that holds one file — a dashboard editing
//! `productivity/supersync/.env` in prod — must never be able to publish
//! a removal of the rest. `put` therefore touches exactly one path, needs
//! no project directory, refreshes the clone first, and either lands its
//! single change on the remote or leaves the clone exactly as the remote
//! is.

use sha2::{Digest, Sha256};

use crate::credentials::CredStore;
use crate::envelope;
use crate::error::LatchError;
use crate::keys;
use crate::lock;
use crate::ops::sync::{project_for, repo_handle, require_escrow};
use crate::platform::Platform;
use crate::repo::{PushOutcome, RefreshState};

/// Which project the file belongs to.
pub enum Target {
    /// By name — no linked directory needed.
    Project(String),
    /// The project linked to this working directory.
    Cwd(String),
}

#[derive(Debug)]
pub struct PutOutcome {
    pub project: String,
    /// False when the stored content already equalled the new content.
    pub pushed: bool,
    /// sha256 of the plaintext now stored, for the caller's next --expect.
    pub sha256: String,
}

pub fn run(
    p: &Platform,
    target: &Target,
    env: &str,
    rel_path: &str,
    content: &[u8],
    expect_sha256: Option<&str>,
    no_escrow: bool,
) -> Result<PutOutcome, LatchError> {
    crate::discovery::validate_env(env)?;
    if crate::groups::parse_member(content).is_some()
        || crate::groups::malformed_pragma(content).is_some()
    {
        return Err(LatchError::other(
            format!("{} carries a group pragma", rel_path),
            "group members are kept in step across projects by 'latch commit'; put writes plain files only",
        ));
    }
    let _lock = lock::acquire(p, 10, || {})?;
    let project = match target {
        Target::Project(name) => name.clone(),
        Target::Cwd(cwd) => project_for(p, cwd)?.name,
    };
    let repo = repo_handle(p)?;
    repo.ensure()?;
    match repo.refresh(true)? {
        RefreshState::Current => {}
        RefreshState::Diverged => {
            return Err(LatchError::other(
                "the local clone holds unpushed changes",
                "put publishes exactly one file and would sweep them along: push them first ('latch push') or discard them ('latch reset')",
            ))
        }
        RefreshState::Offline => unreachable!("refresh(true) errors when offline"),
    }

    let store = CredStore::new(p);
    let key = keys::for_env(&store, &project, env)?.ok_or_else(|| {
        LatchError::other(
            format!("no key for project '{}' ({}) on this machine", project, env),
            "put never creates a key: a file sealed with a key only this machine holds could not be opened anywhere else. Bring the key here with 'latch clone' or 'latch key restore'",
        )
    })?;

    let enc_name = format!("{}.enc", crate::discovery::flatten(rel_path)?);
    let enc_rel = format!("{}/{}/{}", project, env, enc_name);
    let current = match repo.read(&enc_rel)? {
        Some(sealed) => Some(envelope::open(&key.key, &key.id, &sealed, &enc_name)?),
        None => None,
    };
    if let Some(prev) = &current {
        if crate::groups::parse_member(prev).is_some() {
            return Err(LatchError::other(
                format!("{} in {}/{} is a group member", rel_path, project, env),
                "edit the group through a project that holds it and 'latch commit'; put writes plain files only",
            ));
        }
    }
    if let Some(want) = expect_sha256 {
        let have = current
            .as_deref()
            .map(digest)
            .unwrap_or_else(|| "absent".into());
        if !have.eq_ignore_ascii_case(want.trim()) {
            return Err(LatchError::other(
                format!(
                    "{} in {}/{} changed since it was read (expected {}, the remote holds {})",
                    rel_path,
                    project,
                    env,
                    want.trim(),
                    have
                ),
                "read it again ('latch cat'), reapply the edit and retry with the new digest",
            ));
        }
    }
    if current.as_deref() == Some(content) {
        return Ok(PutOutcome {
            project,
            pushed: false,
            sha256: digest(content),
        });
    }

    let sealed = envelope::seal(&key.key, &key.id, content)?;
    let published = (|| {
        repo.write(&enc_rel, &sealed)?;
        require_escrow(p, &repo, &project, env, no_escrow)?;
        repo.push(&format!("put {}/{}/{}", project, env, rel_path), false)
    })();
    match published {
        Ok(PushOutcome::Pushed) => Ok(PutOutcome {
            project,
            pushed: true,
            sha256: digest(content),
        }),
        Ok(PushOutcome::NothingToPush) => Ok(PutOutcome {
            project,
            pushed: false,
            sha256: digest(content),
        }),
        Err(e) => {
            // Leave no half-done change behind for a later push to carry.
            let _ = repo.discard_local();
            Err(e)
        }
    }
}

/// Hex sha256 of a plaintext — the `--expect` currency.
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
