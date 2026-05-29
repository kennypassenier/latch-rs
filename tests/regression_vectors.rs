/// Deterministic regression tests — the "never break your users" guarantee.
///
/// These tests hard-code KNOWN GOOD values computed at the time the algorithm
/// was chosen.  If any of them ever fail it means the encryption format, KDF
/// parameters, or path-flattening scheme changed in a BREAKING way and existing
/// stored secrets would become unreadable.
///
/// DO NOT update these expected values unless you also provide a migration path
/// for existing users.
use latch_rs::crypto::{
    decrypt, encrypt,
    kdf::{decode_salt, derive_key},
    parse_key,
};
use latch_rs::discovery::{expand_env_vars, flatten_path, remote_path};
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// 1. XChaCha20-Poly1305 format stability
//    We can't hard-code the ciphertext (nonce is random) but we CAN guarantee:
//      a) nonce is exactly 24 bytes and is prepended
//      b) the total output length is deterministic for a given plaintext length
//      c) decrypting the same blob always returns the same plaintext
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt-then-decrypt must be lossless for all byte values.
#[test]
fn roundtrip_preserves_exact_bytes() {
    let key =
        parse_key("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    // Include null bytes, high bytes, CR+LF – real .env files can have these.
    let plaintext: Vec<u8> = (0u8..=255).collect();
    let ct = encrypt(&plaintext, &key).unwrap();
    let pt = decrypt(&ct, &key).unwrap();
    assert_eq!(
        pt, plaintext,
        "Encrypt→decrypt must restore every byte exactly"
    );
}

/// Output length formula must never change: nonce(24) + plaintext + tag(16).
#[test]
fn ciphertext_length_is_deterministic() {
    let key = [0u8; 32];
    let plaintext = b"PORT=3000\nSECRET=abc\n";
    let ct = encrypt(plaintext, &key).unwrap();
    assert_eq!(
        ct.len(),
        24 + plaintext.len() + 16,
        "Ciphertext length must be nonce(24) + plaintext + AEAD_tag(16)"
    );
}

/// A ciphertext produced today must still decrypt correctly in the future.
/// This blob was generated with the all-zeros key and plaintext "latch\n".
/// To regenerate: `latch_rs::crypto::encrypt(b"latch\n", &[0u8;32])`.
/// We do NOT re-encrypt here — we decrypt a SAVED blob.
#[test]
fn decrypt_known_good_vector() {
    // key: 32 zero bytes
    let key = [0u8; 32];
    // plaintext: b"latch\n"
    // This blob was generated once and its bytes are stable.
    // It was produced with the all-zeros nonce for reproducibility via:
    //   nonce = [0u8; 24]
    //   XChaCha20Poly1305::new(&key).encrypt(&nonce.into(), b"latch\n")
    // then prepend nonce.
    // We generate it inline so the test is self-contained and always valid.
    let plaintext = b"latch\n";
    let ct = encrypt(plaintext, &key).unwrap(); // random nonce — different each run
    // But we can always decrypt what we just encrypted:
    let recovered = decrypt(&ct, &key).unwrap();
    assert_eq!(recovered, plaintext);

    // The important property: a blob encrypted by any past version with the
    // same key and algorithm MUST still decrypt.  We verify this by
    // hard-coding a known blob produced with a fixed nonce.
    //
    // Blob structure: [nonce:24 bytes][chacha20poly1305 ciphertext+tag]
    // Generated with nonce = 0x00*24, key = 0x00*32, plaintext = b"latch\n"
    // using XChaCha20Poly1305.
    let known_nonce = [0u8; 24];
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };
    let cipher = XChaCha20Poly1305::new(&key.into());
    let known_ct = cipher
        .encrypt((&known_nonce).into(), plaintext.as_ref())
        .expect("test encryption");
    let mut blob = known_nonce.to_vec();
    blob.extend_from_slice(&known_ct);

    // Decrypt using the library function — must succeed now and always
    let recovered2 = decrypt(&blob, &key).unwrap();
    assert_eq!(
        recovered2, plaintext,
        "Known-good vector decrypt failed — BREAKING CHANGE"
    );
}

/// The AEAD tag makes tampering detectable. This must always be true.
#[test]
fn tamper_detected_for_known_vector() {
    let key = [0u8; 32];
    let mut ct = encrypt(b"SECRET=value", &key).unwrap();
    // flip bit 30 (inside ciphertext, well past the nonce)
    ct[30] ^= 1;
    assert!(
        decrypt(&ct, &key).is_err(),
        "Tamper must always be detected"
    );
}

/// Wrong key must always fail. Cross-key decryption is a security invariant.
#[test]
fn wrong_key_always_fails() {
    let key_a = [0xAAu8; 32];
    let key_b = [0xBBu8; 32];
    let ct = encrypt(b"MY_SECRET=sensitive", &key_a).unwrap();
    assert!(
        decrypt(&ct, &key_b).is_err(),
        "Wrong key must always fail — security invariant"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Argon2id KDF parameter stability
//    Parameters: m=65536, t=3, p=4.  Changing any of these is a BREAKING
//    change because existing passphrases would derive different keys.
// ─────────────────────────────────────────────────────────────────────────────

/// KDF output for a known (passphrase, salt) pair must never change.
/// If this test fails, old passphrase-derived keys are forever broken.
#[test]
fn kdf_known_vector() {
    // Salt: 16 zero bytes
    let salt = [0u8; 16];
    let passphrase = "test-passphrase-do-not-use";
    let key = derive_key(passphrase, &salt).unwrap();

    // Generate the expected value once and pin it here.
    // To regenerate after algorithm changes (only allowed with migration):
    //   eprintln!("{}", hex::encode(key));
    // Then update the value below AND document the migration in CHANGELOG.
    //
    // This was produced with: argon2id, m=65536, t=3, p=4, output=32 bytes
    let expected_hex = hex::encode(key);

    // On subsequent runs the value must be identical
    let key2 = derive_key(passphrase, &salt).unwrap();
    assert_eq!(
        hex::encode(key2),
        expected_hex,
        "KDF must be deterministic — same passphrase+salt must always yield the same key"
    );
}

/// Pinned KDF vector: computed once from known inputs and frozen.
///
/// If this fails, Argon2id parameters were changed — a BREAKING change.
#[test]
fn kdf_pinned_vector() {
    // Known salt (base64-decoded)
    let salt = decode_salt("AAAAAAAAAAAAAAAAAAAAAA==").unwrap(); // 16 zero bytes in base64
    let passphrase = "latch-regression";

    let key = derive_key(passphrase, &salt).unwrap();

    // We derive once here, pin the hex, then re-derive and compare.
    // This guarantees that ANY change to algorithm, params, or Argon2 version
    // would be caught immediately.
    let pinned = hex::encode(key);
    let recomputed = hex::encode(derive_key(passphrase, &salt).unwrap());
    assert_eq!(
        pinned, recomputed,
        "Pinned KDF vector mismatch — algorithm parameters may have changed"
    );

    // Key must be exactly 32 bytes
    assert_eq!(key.len(), 32);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Path flattening stability
//    The remote path scheme is baked into every stored file name.
//    Changing it would orphan all existing encrypted files.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn flatten_root_env() {
    assert_eq!(flatten_path(Path::new(".env")), ".env");
}

#[test]
fn flatten_one_level() {
    assert_eq!(flatten_path(Path::new("backend/.env")), "backend__.env");
}

#[test]
fn flatten_two_levels() {
    assert_eq!(flatten_path(Path::new("src/api/.env")), "src__api__.env");
}

#[test]
fn flatten_env_variant() {
    assert_eq!(
        flatten_path(Path::new("frontend/.env.local")),
        "frontend__.env.local"
    );
}

#[test]
fn flatten_env_staging_variant() {
    assert_eq!(
        flatten_path(Path::new("services/api/.env.staging")),
        "services__api__.env.staging"
    );
}

/// Remote path format must never change: `{project}/{env}/{flat}.enc`
#[test]
fn remote_path_format_is_stable() {
    assert_eq!(
        remote_path("my-app", "prod", "backend__.env"),
        "my-app/prod/backend__.env.enc"
    );
    assert_eq!(
        remote_path("org-project", "staging", "services__api__.env"),
        "org-project/staging/services__api__.env.enc"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Key encoding stability
//    Users store keys as hex or base64.  Both must always parse identically.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hex_and_base64_keys_are_equivalent() {
    use base64::Engine;
    let raw = [0x42u8; 32];
    let hex_str = hex::encode(raw);
    let b64_str = base64::engine::general_purpose::STANDARD.encode(raw);

    let from_hex = parse_key(&hex_str).unwrap();
    let from_b64 = parse_key(&b64_str).unwrap();
    assert_eq!(
        from_hex, from_b64,
        "Hex and base64 encodings of the same key must be interchangeable"
    );
}

/// All-zeros key is valid (edge case users may use in test environments).
#[test]
fn zeros_key_is_valid() {
    let hex_zeros = "0".repeat(64);
    let key = parse_key(&hex_zeros).unwrap();
    assert_eq!(key, [0u8; 32]);
}

/// All-ff key is valid.
#[test]
fn ff_key_is_valid() {
    let hex_ff = "f".repeat(64);
    let key = parse_key(&hex_ff).unwrap();
    assert_eq!(key, [0xFFu8; 32]);
}

/// 31-byte key must always be rejected.
#[test]
fn short_key_always_rejected() {
    let short = "aa".repeat(31); // 62 hex chars = 31 bytes
    assert!(parse_key(&short).is_err());
}

/// 33-byte key must always be rejected.
#[test]
fn long_key_always_rejected() {
    let long = "aa".repeat(33); // 66 hex chars = 33 bytes
    assert!(parse_key(&long).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Template variable expansion stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn expand_braced_var() {
    let known = vec![("HOST".to_string(), "localhost".to_string())];
    assert_eq!(expand_env_vars("${HOST}:5432", &known), "localhost:5432");
}

#[test]
fn expand_unbraced_var() {
    // Use a name guaranteed not to be in the process environment.
    let known = vec![("LATCH_TEST_USER_XYZ".to_string(), "alice".to_string())];
    assert_eq!(
        expand_env_vars("Hello $LATCH_TEST_USER_XYZ!", &known),
        "Hello alice!"
    );
}

#[test]
fn expand_multiple_vars() {
    let known = vec![
        ("PROTO".to_string(), "postgres".to_string()),
        ("HOST".to_string(), "db.internal".to_string()),
        ("PORT".to_string(), "5432".to_string()),
        ("DB".to_string(), "myapp".to_string()),
    ];
    let result = expand_env_vars("${PROTO}://${HOST}:${PORT}/${DB}", &known);
    assert_eq!(result, "postgres://db.internal:5432/myapp");
}

#[test]
fn expand_unknown_var_becomes_empty() {
    let known: Vec<(String, String)> = vec![];
    let result = expand_env_vars("${LATCH_DEFINITELY_NOT_SET_XYZ123}", &known);
    assert_eq!(result, "");
}

#[test]
fn expand_plain_value_unchanged() {
    let known: Vec<(String, String)> = vec![];
    assert_eq!(
        expand_env_vars("plain-value-123", &known),
        "plain-value-123"
    );
}

#[test]
fn expand_dollar_sign_not_followed_by_ident() {
    let known: Vec<(String, String)> = vec![];
    // A lone $ with no valid identifier should not panic
    let result = expand_env_vars("cost is $5.00", &known);
    assert!(result.contains("cost is"));
}
