//! Key wrapping (2026-10-30, login redesign): every project and group key
//! is also stored in the secrets repo, sealed under a key derived from ONE
//! master passphrase. A fresh machine then needs only the PAT, the repo
//! and that passphrase to reach every key — the reason the key-backup
//! file used to be mandatory.
//!
//! Layout inside the repo, next to `_escrow` and `_groups`:
//!
//! ```text
//! _keywrap/salt                       16 random bytes, public
//! _keywrap/key~stacks.prod.g2.wrap    one AR10 envelope per slot+generation
//! ```
//!
//! One Argon2 derivation per login: the salt is shared, the derived key
//! seals every wrap. The envelope reuses the pinned format and KDF, so no
//! format break. The slot name sits inside the sealed JSON as well as in
//! the file name; a wrap renamed to another slot is refused on read.
//!
//! The generation is in the file name so "is this key covered?" is
//! answerable without the passphrase (escrow-style warnings).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::kdf::{self, SALT_LEN};
use crate::repo::Repo;

pub const WRAP_PREFIX: &str = "_keywrap";
const SALT_FILE: &str = "_keywrap/salt";
const WRAP_LABEL: &str = "latch-keywrap";
const WRAP_SUFFIX: &str = ".wrap";

pub const MIN_PASSPHRASE_LEN: usize = 20;
/// 32 symbols (no `l`, no `o`, no `0/1`): 5 bits each, 26 symbols = 130 bits.
const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
const GENERATED_LEN: usize = 26;

#[derive(Serialize, Deserialize)]
struct WrapBody {
    slot: String,
    /// hex of the raw slot value (generation prefix included)
    value: String,
}

// ── the passphrase ──────────────────────────────────────────────────────

/// A fresh random passphrase in canonical form (26 symbols, 130 bits).
pub fn generate_passphrase() -> String {
    let mut raw = [0u8; GENERATED_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    // 256 is a multiple of 32, so masking is unbiased.
    raw.iter()
        .map(|b| ALPHABET[(*b & 31) as usize] as char)
        .collect()
}

/// Lowercase, without blanks or dashes: the form that is derived from.
/// Pasting `k7q4-mx2d-…` or the same with spaces must give the same key.
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// `k7q4mx2d…` → `k7q4-mx2d-…` for showing and for the password manager.
pub fn display(canonical: &str) -> String {
    canonical
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn check_strength(canonical: &str) -> Result<(), LatchError> {
    if canonical.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(LatchError::other(
            format!(
                "the master passphrase has {} characters, the minimum is {}",
                canonical.chars().count(),
                MIN_PASSPHRASE_LEN
            ),
            "let latch generate one (leave the choice empty): it is random and 130 bits strong",
        ));
    }
    Ok(())
}

// ── the repo side ───────────────────────────────────────────────────────

/// Does the repo hold a wrap salt, i.e. has a master passphrase been set?
pub fn is_initialised(repo: &Repo) -> Result<bool, LatchError> {
    Ok(read_salt(repo)?.is_some())
}

fn read_salt(repo: &Repo) -> Result<Option<[u8; SALT_LEN]>, LatchError> {
    let Some(raw) = repo.read(SALT_FILE)? else {
        return Ok(None);
    };
    if raw.len() != SALT_LEN {
        return Err(LatchError::Format {
            context: SALT_FILE.into(),
            detail: format!("{} bytes, expected {}", raw.len(), SALT_LEN),
        });
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw);
    Ok(Some(salt))
}

/// The key that seals and opens every wrap. Creates the salt in the
/// clone when `create` is set and none exists yet (the very first
/// setup); never replaces an existing one.
pub fn master_key(
    repo: &Repo,
    canonical_passphrase: &str,
    create: bool,
) -> Result<[u8; KEY_LEN], LatchError> {
    let salt = match read_salt(repo)? {
        Some(s) => s,
        None if create => {
            let mut s = [0u8; SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
            repo.write(SALT_FILE, &s)?;
            s
        }
        None => {
            return Err(LatchError::other(
                "no master passphrase has been set for this secrets repo",
                "run 'latch login --master' on a machine that holds the keys first",
            ))
        }
    };
    kdf::derive_key(canonical_passphrase, &salt)
}

/// `key:stacks.prod` + generation 2 → `_keywrap/key~stacks.prod.g2.wrap`.
pub fn wrap_path(slot: &str, generation: u16) -> String {
    format!(
        "{}/{}.g{}{}",
        WRAP_PREFIX,
        slot.replace(':', "~"),
        generation,
        WRAP_SUFFIX
    )
}

/// The generation a binary slot value carries in its first two bytes.
pub fn generation_of(raw: &[u8]) -> Option<u16> {
    (raw.len() == 2 + KEY_LEN).then(|| u16::from_le_bytes([raw[0], raw[1]]))
}

/// Is this exact key generation present in the repo clone? Needs no
/// passphrase: the file name carries the generation.
pub fn has_wrap(repo: &Repo, slot: &str, generation: u16) -> Result<bool, LatchError> {
    Ok(repo.read(&wrap_path(slot, generation))?.is_some())
}

/// Seal one slot value into the clone. Replaces older generations of the
/// same slot so the repo does not accumulate keys that no ciphertext
/// needs (rotation re-encrypts everything under the new generation).
pub fn wrap(repo: &Repo, master: &[u8; KEY_LEN], slot: &str, raw: &[u8]) -> Result<(), LatchError> {
    let generation = generation_of(raw).ok_or_else(|| {
        LatchError::other(
            format!("{} does not hold a generation-prefixed key", slot),
            "only key: and group: slots can be wrapped",
        )
    })?;
    let body = serde_json::to_vec(&WrapBody {
        slot: slot.to_string(),
        value: hex::encode(raw),
    })
    .expect("wrap body serializes");
    let sealed = envelope::seal(master, &KeyId::new(WRAP_LABEL, 1)?, &body)?;
    repo.write(&wrap_path(slot, generation), &sealed)?;
    let stem = slot.replace(':', "~");
    // `list` is relative to the prefix, so these are bare file names.
    for name in repo.list(WRAP_PREFIX)? {
        if let Some(rest) = name.strip_prefix(&format!("{}.g", stem)) {
            let is_other_generation = rest
                .strip_suffix(WRAP_SUFFIX)
                .and_then(|g| g.parse::<u16>().ok())
                .is_some_and(|g| g != generation);
            if is_other_generation {
                repo.remove(&format!("{}/{}", WRAP_PREFIX, name))?;
            }
        }
    }
    Ok(())
}

/// Open every wrap in the clone. A wrong passphrase fails on the first
/// wrap with `Integrity`; the caller turns that into a plain message.
pub fn unwrap_all(
    repo: &Repo,
    master: &[u8; KEY_LEN],
) -> Result<BTreeMap<String, Vec<u8>>, LatchError> {
    let mut out = BTreeMap::new();
    for name in repo.list(WRAP_PREFIX)? {
        if !name.ends_with(WRAP_SUFFIX) {
            continue;
        }
        let rel = format!("{}/{}", WRAP_PREFIX, name);
        let Some(sealed) = repo.read(&rel)? else {
            continue;
        };
        let plain = envelope::open(master, &KeyId::new(WRAP_LABEL, 1)?, &sealed, &rel)?;
        let body: WrapBody = serde_json::from_slice(&plain).map_err(|e| LatchError::Format {
            context: rel.clone(),
            detail: format!("inner json: {}", e),
        })?;
        let raw = hex::decode(&body.value).map_err(|_| LatchError::Format {
            context: rel.clone(),
            detail: "corrupt hex".into(),
        })?;
        let generation = generation_of(&raw).ok_or_else(|| LatchError::Format {
            context: rel.clone(),
            detail: "wrapped value is not a generation-prefixed key".into(),
        })?;
        if wrap_path(&body.slot, generation) != rel {
            return Err(LatchError::Format {
                context: rel,
                detail: format!(
                    "sealed for {} generation {}, not this file name",
                    body.slot, generation
                ),
            });
        }
        out.insert(body.slot, raw);
    }
    Ok(out)
}
