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
