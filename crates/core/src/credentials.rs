//! Credential storage (K4, AR3, AR11, M4): the resolution chain that works
//! everywhere — environment variables win, then the encrypted credential
//! file, then the OS keyring. Writes always go to the file (M4, 2026-09-26):
//! the keyring on every Linux machine Kenny runs forgets at reboot (on WSL
//! already at the end of a session), so it is only read, never written.
//! The file is one AR10 envelope holding a JSON slot map, keyed by Argon2
//! over a passphrase. A new file is opened by a random machine key kept
//! beside it (`credentials.key`, mode 0600) so nothing ever prompts; a file
//! created with a passphrase keeps prompting, with the tmpfs session cache
//! (AR11) holding the derived key for a TTL.
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
/// M4: the random secret that opens a credential file created without a
/// passphrase. Lives in the latch home next to the file it opens.
pub const MACHINE_KEY_FILE: &str = "credentials.key";
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
        // K1: honor the configured session TTL (Some(0) = never cache =
        // always prompt) instead of ignoring it — the field used to be
        // dead config. A missing/invalid config falls back to the default.
        let session_ttl = crate::config::Config::load(p)
            .ok()
            .and_then(|c| c.session_ttl)
            .unwrap_or(DEFAULT_SESSION_TTL);
        Self { p, session_ttl }
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

    fn machine_key_path(&self) -> String {
        format!("{}/{}", self.p.latch_home, MACHINE_KEY_FILE)
    }

    fn read_machine_key(&self) -> Result<Option<String>, LatchError> {
        Ok(self
            .p
            .files
            .read(&self.machine_key_path())?
            .map(|raw| String::from_utf8_lossy(&raw).trim().to_string())
            .filter(|k| !k.is_empty()))
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

    /// Store a slot. M4 (2026-09-26): always in the FILE, the one store
    /// that survives a reboot on every machine. The keyring used to take
    /// writes whenever it was up, and on Linux it forgets at reboot, which
    /// is how the PAT and every project key vanished twice. Writing where
    /// reads look first also keeps D2b's guarantee: the file shadows the
    /// keyring, so the two can never disagree about a slot.
    pub fn set(&self, slot: &str, value: &[u8]) -> Result<Source, LatchError> {
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
        // First use: create with a new salt. An explicit LATCH_PASSPHRASE
        // still chooses a passphrase file; otherwise M4 mints a machine key
        // so the file never prompts.
        use zeroize::Zeroize;
        let mut passphrase = match self.p.env.var("LATCH_PASSPHRASE") {
            Some(p) => p,
            None => match self.read_machine_key()? {
                Some(k) => k,
                None => {
                    let mut raw = [0u8; KEY_LEN];
                    fill_random(&mut raw);
                    let k = hex::encode(raw);
                    raw.zeroize();
                    self.p
                        .files
                        .write_atomic(&self.machine_key_path(), k.as_bytes())?;
                    k
                }
            },
        };
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let key = kdf::derive_key(&passphrase, &salt)?;
        passphrase.zeroize(); // K1
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
        // D2a: keep the previous file as .bak before overwriting — this is
        // the single file holding every key; a power cut or a bad write
        // must leave a recoverable copy behind, not an empty store.
        if let Some(existing) = self.p.files.read(&self.cred_path())? {
            self.p
                .files
                .write_atomic(&format!("{}.bak", self.cred_path()), &existing)?;
        }
        self.p.files.write_atomic(&self.cred_path(), &cf.encode())
    }

    /// AR11: derived-key session cache in tmpfs. Env passphrase bypasses
    /// everything, then the cache, then the M4 machine key; only a
    /// passphrase file without any of those prompts.
    fn unlock_key(&self, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], LatchError> {
        use zeroize::Zeroize;
        if let Some(mut p) = self.p.env.var("LATCH_PASSPHRASE") {
            let key = kdf::derive_key(&p, salt);
            p.zeroize(); // K1: don't leave the passphrase in memory
            return key;
        }
        if let Some(cached) = self.read_session_key()? {
            return Ok(cached);
        }
        // M4: a file minted with a machine key opens without a prompt. The
        // key is only ever created together with a new file, so where it
        // exists it is the one that file was sealed with.
        if let Some(mut k) = self.read_machine_key()? {
            let key = kdf::derive_key(&k, salt);
            k.zeroize();
            let key = key?;
            self.cache_session_key(&key)?;
            return Ok(key);
        }
        let mut passphrase = self
            .p
            .prompt
            .passphrase("latch credential file passphrase")?;
        let key = kdf::derive_key(&passphrase, salt)?;
        passphrase.zeroize();
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
