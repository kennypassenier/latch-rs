pub mod kdf;

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305,
};
use rand::rngs::OsRng;

/// Number of bytes in an XChaCha20 nonce.
const NONCE_LEN: usize = 24;

/// Encrypt `plaintext` with the given 32-byte key.
///
/// Output layout: `[nonce (24 bytes) || ciphertext + MAC tag]`
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data previously produced by [`encrypt`].
///
/// Returns an error if the nonce is missing, the key is wrong, or the
/// ciphertext has been tampered with (MAC verification failure).
pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        anyhow::bail!(
            "Encrypted blob is too short ({} bytes); expected at least {} bytes",
            data.len(),
            NONCE_LEN
        );
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed (wrong key or tampered data): {}", e))
}

/// Parse a hex- or base64-encoded string into a 32-byte key array.
pub fn parse_key(input: &str) -> Result<[u8; 32]> {
    let bytes = if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(input)?
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(input.trim())?
    };

    if bytes.len() != 32 {
        anyhow::bail!(
            "Key must be exactly 32 bytes (64 hex chars or 44 base64 chars), got {}",
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Generate a cryptographically-random 32-byte key, returning it as a hex string.
pub fn generate_key_hex() -> String {
    let mut key = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    hex::encode(key)
}
