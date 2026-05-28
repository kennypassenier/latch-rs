use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};

/// Derive a 32-byte key from `password` and `salt` using Argon2id.
///
/// Parameters: m=65536 KiB, t=3 iterations, p=4 threads (OWASP recommended).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params =
        Params::new(65_536, 3, 4, Some(32)).map_err(|e| anyhow::anyhow!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {}", e))?;
    Ok(key)
}

/// Generate a random 16-byte Argon2 salt, returned as a base64 string
/// suitable for embedding in configuration files.
pub fn generate_salt_b64() -> String {
    use base64::Engine;
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    base64::engine::general_purpose::STANDARD.encode(salt)
}

/// Decode a base64-encoded salt string back to bytes.
pub fn decode_salt(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow::anyhow!("Invalid salt encoding: {}", e))
}
