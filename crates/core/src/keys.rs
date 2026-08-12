//! Project keys (K-series): 32 random bytes per project, stored through
//! the K4 chain as `key:<project>` with the K3 rotation generation
//! embedded (2 bytes LE || 32 key bytes).

use crate::credentials::CredStore;
use crate::envelope::{KeyId, KEY_LEN};
use crate::error::LatchError;

pub struct ProjectKey {
    pub key: [u8; KEY_LEN],
    pub id: KeyId,
}

pub fn get(store: &CredStore, project: &str) -> Result<Option<ProjectKey>, LatchError> {
    let slot = format!("key:{}", project);
    let Some((raw, _src)) = store.get(&slot)? else {
        return Ok(None);
    };
    decode(project, &raw)
}

pub fn get_or_create(store: &CredStore, project: &str) -> Result<ProjectKey, LatchError> {
    if let Some(k) = get(store, project)? {
        return Ok(k);
    }
    let mut key = [0u8; KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let generation: u16 = 1;
    let mut raw = Vec::with_capacity(2 + KEY_LEN);
    raw.extend_from_slice(&generation.to_le_bytes());
    raw.extend_from_slice(&key);
    store.set(&format!("key:{}", project), &raw)?;
    Ok(ProjectKey {
        key,
        id: KeyId::new(project, generation)?,
    })
}

/// K2: the key label for a project, optionally scoped to one environment.
pub fn label_for(project: &str, env: Option<&str>) -> String {
    match env {
        Some(e) => format!("{}.{}", project, e),
        None => project.to_string(),
    }
}

/// K2 resolution: an environment-scoped key (`key:<project>.<env>`) wins
/// over the project key when it exists — per-env keys isolate blast
/// radius between e.g. dev and prod.
pub fn for_env(
    store: &CredStore,
    project: &str,
    env: &str,
) -> Result<Option<ProjectKey>, LatchError> {
    let scoped = label_for(project, Some(env));
    if let Some((raw, _)) = store.get(&format!("key:{}", scoped))? {
        return decode(&scoped, &raw);
    }
    get(store, project)
}

/// Like [`for_env`], but creates the PROJECT key when neither exists.
/// Env-scoped keys are never created implicitly — only `latch key rotate
/// --env` introduces one (K2/K3), so commit can't silently fork a key.
pub fn for_env_or_create(
    store: &CredStore,
    project: &str,
    env: &str,
) -> Result<ProjectKey, LatchError> {
    if let Some(k) = for_env(store, project, env)? {
        return Ok(k);
    }
    get_or_create(store, project)
}

/// Read the immediately-previous key generation kept during a rotation
/// (B1). Present only while a rotation is in flight or was interrupted.
pub fn prev(store: &CredStore, project: &str, env: Option<&str>) -> Result<Option<ProjectKey>, LatchError> {
    let label = label_for(project, env);
    let Some((raw, _)) = store.get(&format!("key:{}#prev", label))? else {
        return Ok(None);
    };
    decode(&label, &raw)
}

/// Clear the preserved previous key — called once a rotation has fully
/// re-encrypted and can no longer need the old generation.
pub fn clear_prev(store: &CredStore, project: &str, env: Option<&str>) -> Result<(), LatchError> {
    let label = label_for(project, env);
    store.delete(&format!("key:{}#prev", label))
}

/// The key that opens ciphertext sealed at `generation`: the current key,
/// the preserved previous key, or none. Lets read paths survive a
/// half-finished rotation (B1) instead of reporting Corrupt.
pub fn for_generation(
    store: &CredStore,
    project: &str,
    env: Option<&str>,
    generation: u16,
) -> Result<Option<ProjectKey>, LatchError> {
    let cur = match env {
        Some(e) => for_env(store, project, e)?,
        None => get(store, project)?,
    };
    if let Some(k) = cur {
        if k.id.generation == generation {
            return Ok(Some(k));
        }
    }
    match prev(store, project, env)? {
        Some(k) if k.id.generation == generation => Ok(Some(k)),
        _ => Ok(None),
    }
}

/// K3: mint the next generation for the project key or an env-scoped key
/// (creating the env scope if this is its first rotation). The OLD key is
/// preserved under `key:<label>#prev` BEFORE the new key is stored, so a
/// crash mid-re-encryption never destroys the only copy of the old key
/// (B1) — recovery opens every ciphertext with current-or-prev, and a
/// re-run finishes the job. Returns (previously-resolved key, new key);
/// the caller re-encrypts, then calls [`clear_prev`].
pub fn rotate(
    store: &CredStore,
    project: &str,
    env: Option<&str>,
) -> Result<(Option<ProjectKey>, ProjectKey), LatchError> {
    let old = match env {
        Some(e) => for_env(store, project, e)?,
        None => get(store, project)?,
    };
    let label = label_for(project, env);
    // Preserve the old key first (crash-safe ordering).
    if let Some(o) = &old {
        let mut raw = Vec::with_capacity(2 + KEY_LEN);
        raw.extend_from_slice(&o.id.generation.to_le_bytes());
        raw.extend_from_slice(&o.key);
        store.set(&format!("key:{}#prev", label), &raw)?;
    }
    let generation = old.as_ref().map(|k| k.id.generation + 1).unwrap_or(1);
    let mut key = [0u8; KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let mut raw = Vec::with_capacity(2 + KEY_LEN);
    raw.extend_from_slice(&generation.to_le_bytes());
    raw.extend_from_slice(&key);
    store.set(&format!("key:{}", label), &raw)?;
    Ok((
        old,
        ProjectKey {
            key,
            id: KeyId::new(label, generation)?,
        },
    ))
}

fn decode(project: &str, raw: &[u8]) -> Result<Option<ProjectKey>, LatchError> {
    if raw.len() != 2 + KEY_LEN {
        return Err(LatchError::Format {
            context: format!("key:{}", project),
            detail: format!(
                "stored key has {} bytes, expected {}",
                raw.len(),
                2 + KEY_LEN
            ),
        });
    }
    let generation = u16::from_le_bytes([raw[0], raw[1]]);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw[2..]);
    Ok(Some(ProjectKey {
        key,
        id: KeyId::new(project, generation)?,
    }))
}
