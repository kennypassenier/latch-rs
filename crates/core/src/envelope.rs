//! The ciphertext envelope (AR10) and authenticated encryption (K1).
//!
//! Wire format (all integers little-endian):
//!
//! ```text
//! magic    6 bytes   b"LATCH2"
//! version  1 byte    0x02
//! keyid_len 1 byte   n (1..=255)
//! key_id   n bytes   utf-8, e.g. "homelab" / "homelab.prod" / "group:smtp_creds.dev"
//! gen      2 bytes   key generation (K3 rotation counter, starts at 1)
//! nonce    24 bytes  XChaCha20 nonce
//! body     rest      XChaCha20-Poly1305 ciphertext+tag
//! ```
//!
//! The entire header (everything before `body`) is fed to the AEAD as
//! associated data: flipping ANY header byte — even the key-id label —
//! breaks authentication. Wrong-key vs corruption stays distinguishable
//! because the key-id is read (and reported) before decryption is
//! attempted; a *forged* key-id then fails authentication anyway.
//!
//! Format rules: sealing always writes the CURRENT version. Opening reads
//! v2 only (clean break, AR4); an unknown version is a Format error that
//! names it, so a future v3 binary can migrate and an old binary says
//! "update me" instead of "corrupt".

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::LatchError;

pub const MAGIC: &[u8; 6] = b"LATCH2";
pub const VERSION: u8 = 2;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
const GEN_LEN: usize = 2;
const MIN_HEADER: usize = MAGIC.len() + 1 + 1 + 1 + GEN_LEN + NONCE_LEN;

/// Identifies which key sealed an envelope (AR10): a label plus the K3
/// rotation generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId {
    pub label: String,
    pub generation: u16,
}

impl KeyId {
    pub fn new(label: impl Into<String>, generation: u16) -> Result<Self, LatchError> {
        let label = label.into();
        if label.is_empty() || label.len() > 255 {
            return Err(LatchError::other(
                format!("invalid key label length {}", label.len()),
                "labels are 1-255 bytes; this is a caller bug",
            ));
        }
        Ok(Self { label, generation })
    }
}

/// Seal `plaintext` under `key` (32 bytes), stamping the key identity into
/// the authenticated header. `nonce` is normally random; it is a parameter
/// so the regression vectors can pin the exact output bytes.
pub fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    key_id: &KeyId,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, LatchError> {
    let mut header = Vec::with_capacity(MIN_HEADER + key_id.label.len());
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(key_id.label.len() as u8);
    header.extend_from_slice(key_id.label.as_bytes());
    header.extend_from_slice(&key_id.generation.to_le_bytes());
    header.extend_from_slice(nonce);

    let cipher = XChaCha20Poly1305::new(key.into());
    let body = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| {
            LatchError::other("encryption failed", "this is a bug in latch — report it")
        })?;

    header.extend_from_slice(&body);
    Ok(header)
}

/// Seal with a fresh random nonce (the normal path).
pub fn seal(key: &[u8; KEY_LEN], key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, LatchError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    seal_with_nonce(key, key_id, &nonce, plaintext)
}

/// Read only the header — which key would be needed? Used by S6 verify and
/// by open() to report WrongKey before attempting decryption.
pub fn peek_key_id(envelope: &[u8], context: &str) -> Result<KeyId, LatchError> {
    if envelope.len() < MIN_HEADER {
        return Err(LatchError::Format {
            context: context.into(),
            detail: format!(
                "too short to be a latch envelope ({} bytes)",
                envelope.len()
            ),
        });
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        return Err(LatchError::Format {
            context: context.into(),
            detail: "missing LATCH2 magic".into(),
        });
    }
    let version = envelope[MAGIC.len()];
    if version != VERSION {
        return Err(LatchError::Format {
            context: context.into(),
            detail: format!("format version {} (this binary reads {})", version, VERSION),
        });
    }
    let keyid_len = envelope[MAGIC.len() + 1] as usize;
    let label_start = MAGIC.len() + 2;
    let label_end = label_start + keyid_len;
    if keyid_len == 0 || envelope.len() < label_end + GEN_LEN + NONCE_LEN {
        return Err(LatchError::Format {
            context: context.into(),
            detail: "truncated header".into(),
        });
    }
    let label = std::str::from_utf8(&envelope[label_start..label_end])
        .map_err(|_| LatchError::Format {
            context: context.into(),
            detail: "key label is not utf-8".into(),
        })?
        .to_string();
    let generation = u16::from_le_bytes([envelope[label_end], envelope[label_end + 1]]);
    Ok(KeyId { label, generation })
}

/// Open an envelope. `expected` is the identity of the key the caller
/// holds: a mismatch reports WrongKey (with what IS needed) without ever
/// touching the cipher; a match that fails authentication is Integrity.
pub fn open(
    key: &[u8; KEY_LEN],
    expected: &KeyId,
    envelope: &[u8],
    context: &str,
) -> Result<Vec<u8>, LatchError> {
    let found = peek_key_id(envelope, context)?;
    if found != *expected {
        return Err(LatchError::WrongKey {
            context: context.into(),
            needed: found.label,
            generation: found.generation,
        });
    }
    let label_end = MAGIC.len() + 2 + found.label.len();
    let nonce_start = label_end + GEN_LEN;
    let body_start = nonce_start + NONCE_LEN;
    let header = &envelope[..body_start];
    let nonce = &envelope[nonce_start..body_start];
    let body = &envelope[body_start..];

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: header,
            },
        )
        .map_err(|_| LatchError::Integrity {
            context: context.into(),
        })
}
