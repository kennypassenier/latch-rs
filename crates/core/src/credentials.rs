//! Credential storage (K4, AR3, AR11): the resolution chain that works
//! everywhere — environment variables win, then the encrypted credential
//! file, then the OS keyring. Writes go to the keyring where available,
//! otherwise to the file. The file is one AR10 envelope holding a JSON
//! slot map, keyed by an Argon2 passphrase; a tmpfs session cache (AR11)
//! keeps the derived key for a TTL so interactive use prompts once, not
//! per command.
//!
//! Slot names: `pat` (GitHub token), `key:<project>`,
//! `key:<project>.<env>`, `group:<name>.<env>` — the env-var override for
//! a slot is `LATCH_` + slot uppercased with `:`/`.`/`-` → `_`
//! (e.g. `key:homelab.prod` → `LATCH_KEY_HOMELAB_PROD`).

use serde::{Deserialize, Serialize};

use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::kdf::{self, SALT_LEN};
use crate::platform::Platform;

pub const CRED_FILE: &str = "credentials.enc";
const CRED_KEY_LABEL: &str = "latch-credentials";
/// Default AR11 session TTL in seconds; 0 disables caching.
pub const DEFAULT_SESSION_TTL: u64 = 15 * 60;

/// Where a credential came from — surfaced by W8 state/doctor and the G3
/// matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    EnvVar,
    File,
    Keyring,
}

#[derive(Serialize, Deserialize, Default)]
struct SlotMap {
    #[serde(default)]
    slots: std::collections::BTreeMap<String, String>, // slot -> base64-ish hex
}

/// On-disk shape of the credential file: salt + envelope. The salt lives
/// outside the envelope (it is needed to derive the key that opens it) but
/// any tampering with it changes the derived key and fails authentication.
struct CredFile {
    salt: [u8; SALT_LEN],
    envelope: Vec<u8>,
}

impl CredFile {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SALT_LEN + self.envelope.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.envelope);
        out
    }
    fn decode(raw: &[u8]) -> Result<Self, LatchError> {
        if raw.len() < SALT_LEN {
            return Err(LatchError::Format {
                context: CRED_FILE.into(),
                detail: "too short".into(),
            });
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[..SALT_LEN]);
        Ok(Self {
            salt,
            envelope: raw[SALT_LEN..].to_vec(),
        })
    }
}

pub fn env_var_for_slot(slot: &str) -> String {
    let mut name = String::from("LATCH_");
    for c in slot.chars() {
        match c {
            ':' | '.' | '-' => name.push('_'),
            c => name.push(c.to_ascii_uppercase()),
        }
    }
    name
}

pub struct CredStore<'a> {
    p: &'a Platform<'a>,
    session_ttl: u64,
}

impl<'a> CredStore<'a> {
    pub fn new(p: &'a Platform<'a>) -> Self {
        Self {
            p,
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }

    pub fn with_session_ttl(p: &'a Platform<'a>, ttl: u64) -> Self {
        Self {
            p,
            session_ttl: ttl,
        }
    }

    fn cred_path(&self) -> String {
        format!("{}/{}", self.p.latch_home, CRED_FILE)
    }

    fn session_path(&self) -> Option<String> {
        self.p
            .runtime_dir
            .as_ref()
            .map(|d| format!("{}/session.key", d))
    }

    /// Resolve a slot (K4): env → file → keyring. Returns the value and
    /// where it came from. Binary slots (`key:` / `group:`) are carried as
    /// hex in environment variables — env vars are text; the file and
    /// keyring layers store raw bytes.
    pub fn get(&self, slot: &str) -> Result<Option<(Vec<u8>, Source)>, LatchError> {
        if let Some(v) = self.p.env.var(&env_var_for_slot(slot)) {
            let value = if slot.starts_with("key:") || slot.starts_with("group:") {
                hex::decode(v.trim()).map_err(|_| {
                    LatchError::other(
                        format!("{} is not valid hex", env_var_for_slot(slot)),
                        "binary key slots are injected as hex (latch key show prints the right form)",
                    )
                })?
            } else {
                v.into_bytes()
            };
            return Ok(Some((value, Source::EnvVar)));
        }
        if let Some(map) = self.read_file_map()? {
            if let Some(hexed) = map.slots.get(slot) {
                let raw = hex_decode(hexed, slot)?;
                return Ok(Some((raw, Source::File)));
            }
        }
        if self.p.keyring.available() {
            if let Some(v) = self.p.keyring.get(slot)? {
                return Ok(Some((v, Source::Keyring)));
            }
        }
        Ok(None)
    }

    /// Store a slot: keyring where available, otherwise the encrypted file
    /// (creating it — with a passphrase — on first use).
    pub fn set(&self, slot: &str, value: &[u8]) -> Result<Source, LatchError> {
        if self.p.keyring.available() {
            self.p.keyring.set(slot, value)?;
            return Ok(Source::Keyring);
        }
        let (mut map, salt, key) = self.open_or_create_file()?;
        map.slots.insert(slot.into(), hex::encode(value));
        self.write_file_map(&map, &salt, &key)?;
        Ok(Source::File)
    }

    pub fn delete(&self, slot: &str) -> Result<(), LatchError> {
        if self.p.keyring.available() {
            self.p.keyring.delete(slot)?;
        }
        if self.p.files.read(&self.cred_path())?.is_some() {
            let (mut map, salt, key) = self.open_or_create_file()?;
            map.slots.remove(slot);
            self.write_file_map(&map, &salt, &key)?;
        }
        Ok(())
    }

    /// Slot names stored in the FILE backend (K6 backup enumeration).
    /// Keyring backends cannot enumerate; callers union this with the
    /// deterministic candidates derived from config + repo layout.
    pub fn file_slots(&self) -> Result<Vec<String>, LatchError> {
        Ok(self
            .read_file_map()?
            .map(|m| m.slots.keys().cloned().collect())
            .unwrap_or_default())
    }

    /// Sources report for W8/G3: does the file exist, is the keyring up,
    /// is a session active.
    pub fn file_exists(&self) -> Result<bool, LatchError> {
        Ok(self.p.files.read(&self.cred_path())?.is_some())
    }

    // ── file backend internals ─────────────────────────────────────────

    fn read_file_map(&self) -> Result<Option<SlotMap>, LatchError> {
        let Some(raw) = self.p.files.read(&self.cred_path())? else {
            return Ok(None);
        };
        let cf = CredFile::decode(&raw)?;
        let key = self.unlock_key(&cf.salt)?;
        let plain = envelope::open(
            &key,
            &KeyId::new(CRED_KEY_LABEL, 1)?,
            &cf.envelope,
            CRED_FILE,
        )?;
        let map: SlotMap = serde_json::from_slice(&plain).map_err(|e| LatchError::Format {
            context: CRED_FILE.into(),
            detail: format!("inner json: {}", e),
        })?;
        Ok(Some(map))
    }

    fn open_or_create_file(&self) -> Result<(SlotMap, [u8; SALT_LEN], [u8; KEY_LEN]), LatchError> {
        if let Some(raw) = self.p.files.read(&self.cred_path())? {
            let cf = CredFile::decode(&raw)?;
            let key = self.unlock_key(&cf.salt)?;
            let plain = envelope::open(
                &key,
                &KeyId::new(CRED_KEY_LABEL, 1)?,
                &cf.envelope,
                CRED_FILE,
            )?;
            let map: SlotMap = serde_json::from_slice(&plain).map_err(|e| LatchError::Format {
                context: CRED_FILE.into(),
                detail: format!("inner json: {}", e),
            })?;
            return Ok((map, cf.salt, key));
        }
        // First use: create with a new salt and a passphrase.
        let passphrase = match self.p.env.var("LATCH_PASSPHRASE") {
            Some(p) => p,
            None => self.p.prompt.passphrase(
                "no OS keyring here — set a passphrase for the latch credential file",
            )?,
        };
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key = kdf::derive_key(&passphrase, &salt)?;
        self.cache_session_key(&key)?;
        Ok((SlotMap::default(), salt, key))
    }

    fn write_file_map(
        &self,
        map: &SlotMap,
        salt: &[u8; SALT_LEN],
        key: &[u8; KEY_LEN],
    ) -> Result<(), LatchError> {
        let plain = serde_json::to_vec(map).map_err(|e| LatchError::Format {
            context: CRED_FILE.into(),
            detail: format!("encode: {}", e),
        })?;
        let sealed = envelope::seal(key, &KeyId::new(CRED_KEY_LABEL, 1)?, &plain)?;
        let cf = CredFile {
            salt: *salt,
            envelope: sealed,
        };
        self.p.files.write_atomic(&self.cred_path(), &cf.encode())
    }

    /// AR11: derived-key session cache in tmpfs. Env passphrase bypasses
    /// everything; a fresh prompt refreshes the cache.
    fn unlock_key(&self, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], LatchError> {
        if let Some(p) = self.p.env.var("LATCH_PASSPHRASE") {
            return kdf::derive_key(&p, salt);
        }
        if let Some(cached) = self.read_session_key()? {
            return Ok(cached);
        }
        let passphrase = self
            .p
            .prompt
            .passphrase("latch credential file passphrase")?;
        let key = kdf::derive_key(&passphrase, salt)?;
        self.cache_session_key(&key)?;
        Ok(key)
    }

    fn read_session_key(&self) -> Result<Option<[u8; KEY_LEN]>, LatchError> {
        if self.session_ttl == 0 {
            return Ok(None);
        }
        let Some(path) = self.session_path() else {
            return Ok(None);
        };
        let Some(mtime) = self.p.files.mtime_unix(&path)? else {
            return Ok(None);
        };
        if self.p.clock.now_unix().saturating_sub(mtime) > self.session_ttl {
            self.p.files.remove(&path)?;
            return Ok(None);
        }
        let Some(raw) = self.p.files.read(&path)? else {
            return Ok(None);
        };
        if raw.len() != KEY_LEN {
            self.p.files.remove(&path)?;
            return Ok(None);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&raw);
        Ok(Some(key))
    }

    fn cache_session_key(&self, key: &[u8; KEY_LEN]) -> Result<(), LatchError> {
        if self.session_ttl == 0 {
            return Ok(());
        }
        if let Some(path) = self.session_path() {
            self.p.files.write_atomic(&path, key)?;
        }
        Ok(())
    }
}

fn hex_decode(s: &str, slot: &str) -> Result<Vec<u8>, LatchError> {
    hex::decode(s).map_err(|_| LatchError::Format {
        context: format!("credential slot {}", slot),
        detail: "corrupt hex".into(),
    })
}

fn fill_random(buf: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
}
