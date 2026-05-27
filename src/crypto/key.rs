use crate::error::{LatchError, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub data: Vec<u8>,
}

/// The mode used to derive the encryption key
#[derive(Debug, Clone)]
pub enum SecretDerivationMode {
    /// Use a raw secret key (base64 encoded)
    Key(RawSecretKey),
    /// Use a passphrase/password that will be hashed
    Passphrase(String),
}

#[derive(Debug, Clone)]
pub struct RawSecretKey {
    pub data: Vec<u8>,
}

impl RawSecretKey {
    pub fn from_bytes(data: &[u8]) -> Self {
        RawSecretKey {
            data: data.to_vec(),
        }
    }
}

/// Derive a key from a raw secret key using SHA256
pub fn derive_key_from_raw(secret_key: &SecretKey) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(&secret_key.data);
    Ok(hasher.finalize().to_vec())
}
