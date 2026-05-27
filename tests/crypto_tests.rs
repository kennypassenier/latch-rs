use latch_rs::crypto::kdf::{decode_salt, derive_key, generate_salt_b64};
/// Crypto integration tests
///
/// Run with: cargo test --test crypto_tests
use latch_rs::crypto::{decrypt, encrypt, generate_key_hex, parse_key};

// ── Roundtrip ─────────────────────────────────────────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let plaintext = b"SECRET=hunter2\nPORT=3000\n";
    let ciphertext = encrypt(plaintext, &key).unwrap();
    let recovered = decrypt(&ciphertext, &key).unwrap();
    assert_eq!(plaintext.to_vec(), recovered);
}

#[test]
fn nonce_is_prepended_and_unique() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let msg = b"hello";
    let c1 = encrypt(msg, &key).unwrap();
    let c2 = encrypt(msg, &key).unwrap();
    // Output must be at least nonce (24) + ciphertext + tag (16) long
    assert!(c1.len() >= 24 + msg.len() + 16);
    // Two encryptions of the same plaintext must produce different nonces/ciphertext
    assert_ne!(c1, c2);
}

// ── Tamper detection ──────────────────────────────────────────────────────────

#[test]
fn tampered_ciphertext_fails_mac_check() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let mut ciphertext = encrypt(b"sensitive data", &key).unwrap();
    // Flip a byte in the ciphertext portion (after the 24-byte nonce)
    let flip_idx = 30;
    ciphertext[flip_idx] ^= 0xFF;
    let result = decrypt(&ciphertext, &key);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail decryption"
    );
    let msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        msg.contains("tampered") || msg.contains("fail") || msg.contains("wrong"),
        "Error should mention tamper/failure, got: {}",
        msg
    );
}

#[test]
fn wrong_key_fails_decryption() {
    let key1 = parse_key(&generate_key_hex()).unwrap();
    let key2 = parse_key(&generate_key_hex()).unwrap();
    let ciphertext = encrypt(b"secret", &key1).unwrap();
    assert!(decrypt(&ciphertext, &key2).is_err());
}

#[test]
fn truncated_blob_errors_gracefully() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let result = decrypt(&[0u8; 10], &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too short"));
}

// ── Key parsing ───────────────────────────────────────────────────────────────

#[test]
fn parse_hex_key() {
    let hex = generate_key_hex();
    assert_eq!(hex.len(), 64);
    let key = parse_key(&hex).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn parse_base64_key() {
    use base64::Engine;
    let raw = [0xABu8; 32];
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let key = parse_key(&b64).unwrap();
    assert_eq!(key, raw);
}

#[test]
fn parse_key_wrong_length_errors() {
    // 31 bytes hex = 62 chars – should fail
    let short_hex = "00".repeat(31);
    assert!(parse_key(&short_hex).is_err());
}

// ── KDF ───────────────────────────────────────────────────────────────────────

#[test]
fn kdf_is_deterministic() {
    let salt_b64 = generate_salt_b64();
    let salt = decode_salt(&salt_b64).unwrap();
    let k1 = derive_key("my passphrase", &salt).unwrap();
    let k2 = derive_key("my passphrase", &salt).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn kdf_different_passphrases_different_keys() {
    let salt = decode_salt(&generate_salt_b64()).unwrap();
    let k1 = derive_key("passA", &salt).unwrap();
    let k2 = derive_key("passB", &salt).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_different_salts_different_keys() {
    let salt1 = decode_salt(&generate_salt_b64()).unwrap();
    let salt2 = decode_salt(&generate_salt_b64()).unwrap();
    let k1 = derive_key("same passphrase", &salt1).unwrap();
    let k2 = derive_key("same passphrase", &salt2).unwrap();
    assert_ne!(k1, k2);
}
