//! Is a project's key covered by a second copy? Since 2026-10-30 this is
//! a WARNING, never a refusal (Kenny: "Optioneel met waarschuwing"): the
//! key wraps under the master passphrase and the optional backup file
//! both count as cover, and `latch push` / `latch put` publish either way.
//! Reads only the local clone, no network.

use crate::credentials::CredStore;
use crate::error::LatchError;
use crate::keys;
use crate::keywrap;
use crate::ops::sync::repo_handle;
use crate::platform::Platform;
use crate::repo::Repo;

/// True when the exact generation of this slot's key is in the repo as a
/// wrap, or a backup was recorded for it.
pub fn is_covered(repo: &Repo, label: &str, generation: u16) -> Result<bool, LatchError> {
    Ok(
        keywrap::has_wrap(repo, &format!("key:{}", label), generation)?
            || crate::escrow::has(repo, label, generation)?,
    )
}

/// The sentence to print after a publish, or None when the key is covered
/// (or there is no key here, so nothing sealed by this machine).
pub fn warning(p: &Platform, project: &str, env: &str) -> Result<Option<String>, LatchError> {
    let store = CredStore::new(p);
    let Some(key) = keys::for_env(&store, project, env)? else {
        return Ok(None);
    };
    let repo = repo_handle(p)?;
    if is_covered(&repo, &key.id.label, key.id.generation)? {
        return Ok(None);
    }
    Ok(Some(format!(
        "warning: key '{}' (generation {}) exists on this machine only :: run 'latch login --master' to put it under your master passphrase in the repo (or 'latch key backup <file>' for an offline copy)",
        key.id.label, key.id.generation
    )))
}
