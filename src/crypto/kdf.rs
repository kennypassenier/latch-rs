use crate::crypto::{SecretDerivationMode, SecretKey};
use crate::error::Result;
use sha2::{Digest, Sha256};

/// Derive a key from a secret using SHA256
pub fn derive_key_from_secret(secret: &SecretDerivationMode, data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    match secret {
        SecretDerivationMode::Key(key) => {
            hasher.update(&key.data);
        }
        SecretDerivationMode::Passphrase(passphrase) => {
            hasher.update(passphrase.as_bytes());
        }
    }
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}
