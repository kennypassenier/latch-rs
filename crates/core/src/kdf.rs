//! Passphrase → key derivation (AR3): Argon2id with pinned parameters.
//! Used by the credential file (K4 fallback) and key backups (K6). The
//! parameters are part of the on-disk format — changing them is a format
//! version bump, never a silent edit (the regression vector enforces it).

use argon2::{Algorithm, Argon2, Params, Version};

use crate::envelope::KEY_LEN;
use crate::error::LatchError;

/// Pinned Argon2id parameters (v2 format): 64 MiB, 3 passes, 1 lane.
/// Sized for interactive use on a small LXC without being trivial.
pub const M_COST_KIB: u32 = 64 * 1024;
pub const T_COST: u32 = 3;
pub const P_COST: u32 = 1;
pub const SALT_LEN: usize = 16;

pub fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], LatchError> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(KEY_LEN)).map_err(|e| {
        LatchError::KeyDerivation {
            detail: format!("bad Argon2 params: {}", e),
        }
    })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| LatchError::KeyDerivation {
            detail: format!("argon2: {}", e),
        })?;
    Ok(out)
}
