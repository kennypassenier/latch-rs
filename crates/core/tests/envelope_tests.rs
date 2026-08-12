//! K1/AR10 tests incl. the PINNED regression vector: if any refactor
//! changes a single output byte of the format, these fail (AR7 rule — the
//! format never changes silently).

use latch_core::envelope::{open, peek_key_id, seal_with_nonce, KeyId, KEY_LEN, NONCE_LEN};
use latch_core::error::LatchError;
use latch_core::kdf::{derive_key, SALT_LEN};

fn fixed_key() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

fn fixed_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    for (i, b) in n.iter_mut().enumerate() {
        *b = 0xA0 ^ (i as u8);
    }
    n
}

#[test]
fn round_trip() {
    let key = fixed_key();
    let id = KeyId::new("homelab", 1).unwrap();
    let sealed = seal_with_nonce(&key, &id, &fixed_nonce(), b"SECRET=1\n").unwrap();
    let opened = open(&key, &id, &sealed, "test").unwrap();
    assert_eq!(opened, b"SECRET=1\n");
}

#[test]
fn pinned_regression_vector() {
    // THE format contract. Never update this constant to make a test pass —
    // a mismatch means the on-disk format changed, which is a version bump.
    let key = fixed_key();
    let id = KeyId::new("homelab", 1).unwrap();
    let sealed = seal_with_nonce(&key, &id, &fixed_nonce(), b"SECRET=1\n").unwrap();
    let expected = "4c41544348320207686f6d656c61620100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b716a9494ff209999d6b922daf9b628c036ad7d7fe6e36325534";
    assert_eq!(hex::encode(&sealed), expected);
}

#[test]
fn header_prefix_is_stable_and_readable() {
    let sealed = seal_with_nonce(
        &fixed_key(),
        &KeyId::new("homelab.prod", 3).unwrap(),
        &fixed_nonce(),
        b"x",
    )
    .unwrap();
    assert_eq!(&sealed[..6], b"LATCH2");
    assert_eq!(sealed[6], 2, "format version byte");
    let peeked = peek_key_id(&sealed, "t").unwrap();
    assert_eq!(peeked.label, "homelab.prod");
    assert_eq!(peeked.generation, 3);
}

#[test]
fn any_flipped_byte_fails_closed() {
    let key = fixed_key();
    let id = KeyId::new("homelab", 1).unwrap();
    let sealed = seal_with_nonce(&key, &id, &fixed_nonce(), b"SECRET=1\n").unwrap();
    for pos in 0..sealed.len() {
        let mut evil = sealed.clone();
        evil[pos] ^= 0x01;
        let out = open(&key, &id, &evil, "t");
        assert!(out.is_err(), "flipped byte {} still decrypted", pos);
    }
}

#[test]
fn truncation_fails_closed() {
    let key = fixed_key();
    let id = KeyId::new("homelab", 1).unwrap();
    let sealed = seal_with_nonce(&key, &id, &fixed_nonce(), b"SECRET=1\n").unwrap();
    for len in 0..sealed.len() {
        assert!(open(&key, &id, &sealed[..len], "t").is_err(), "len {}", len);
    }
}

#[test]
fn wrong_key_is_reported_with_what_is_needed() {
    let key = fixed_key();
    let sealed = seal_with_nonce(
        &key,
        &KeyId::new("homelab.prod", 3).unwrap(),
        &fixed_nonce(),
        b"x",
    )
    .unwrap();
    let err = open(
        &key,
        &KeyId::new("homelab.dev", 1).unwrap(),
        &sealed,
        "file.env",
    )
    .unwrap_err();
    match err {
        LatchError::WrongKey {
            needed, generation, ..
        } => {
            assert_eq!(needed, "homelab.prod");
            assert_eq!(generation, 3);
        }
        other => panic!("expected WrongKey, got {other}"),
    }
}

#[test]
fn v1_and_future_formats_are_named_not_garbled() {
    let err = peek_key_id(b"not an envelope at all........", "old.env").unwrap_err();
    assert!(matches!(err, LatchError::Format { .. }));
    let msg = format!("{err}");
    assert!(
        msg.contains("v1") || msg.contains("LATCH2"),
        "remedy mentions the situation: {msg}"
    );
    let key = fixed_key();
    let id = KeyId::new("homelab", 1).unwrap();
    let mut sealed = seal_with_nonce(&key, &id, &fixed_nonce(), b"x").unwrap();
    sealed[6] = 3;
    let err = open(&key, &id, &sealed, "t").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("version 3"), "{msg}");
    assert!(
        msg.contains("latch update"),
        "remedy tells the user to update: {msg}"
    );
}

#[test]
fn kdf_pinned_vector() {
    // Argon2id parameters are part of the format (AR3) — pinned.
    let salt = [7u8; SALT_LEN];
    let key = derive_key("correct horse battery staple", &salt).unwrap();
    let expected = "6ad10af97f1744119bd7135c85121dc589794f9c5d646200b8ad4d6becf15084";
    assert_eq!(hex::encode(key), expected);
}

#[test]
fn every_error_carries_a_remedy() {
    let errors: Vec<LatchError> = vec![
        LatchError::Integrity {
            context: "x".into(),
        },
        LatchError::WrongKey {
            context: "x".into(),
            needed: "k".into(),
            generation: 1,
        },
        LatchError::Format {
            context: "x".into(),
            detail: "d".into(),
        },
        LatchError::KeyDerivation { detail: "d".into() },
        LatchError::other("w", "do the thing"),
    ];
    for e in errors {
        let msg = format!("{e}");
        assert!(msg.contains("::"), "no remedy separator in: {msg}");
    }
}
