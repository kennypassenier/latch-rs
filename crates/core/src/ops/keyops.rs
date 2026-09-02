//! Key management verbs: K5 show, K3 rotate (also the K2 entry point for
//! per-env keys), K6 backup/restore.

use crate::credentials::{env_var_for_slot, CredStore, Source};
use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::kdf::{self, SALT_LEN};
use crate::keys;
use crate::lock;
use crate::platform::Platform;

use super::consume::repo_handle;
use super::sync::project_for;

// ── K5 · latch key show ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct KeyInfo {
    pub label: String,
    pub generation: u16,
    pub source: Source,
    /// The env-var injection form (`LATCH_KEY_...`), always shown.
    pub env_var: String,
    /// Hex of generation+key — only with an explicit `--reveal` (K5: a key
    /// never reaches a terminal by accident).
    pub hex: Option<String>,
}

pub fn show(
    p: &Platform,
    cwd: &str,
    env: Option<&str>,
    reveal: bool,
) -> Result<KeyInfo, LatchError> {
    let proj = project_for(p, cwd)?;
    let store = CredStore::new(p);
    let label = keys::label_for(&proj.name, env);
    let slot = format!("key:{}", label);
    let Some((raw, source)) = store.get(&slot)? else {
        return Err(LatchError::other(
            format!("no key stored for '{}'", label),
            "a project key is created on first 'latch commit'; env keys via 'latch key rotate --env'",
        ));
    };
    if raw.len() != 2 + KEY_LEN {
        return Err(LatchError::Format {
            context: slot,
            detail: format!(
                "stored key has {} bytes, expected {}",
                raw.len(),
                2 + KEY_LEN
            ),
        });
    }
    Ok(KeyInfo {
        label,
        generation: u16::from_le_bytes([raw[0], raw[1]]),
        source,
        env_var: env_var_for_slot(&slot),
        hex: reveal.then(|| hex::encode(&raw)),
    })
}

// ── K3 · latch key rotate ───────────────────────────────────────────────

pub const ROTATE_CAVEAT: &str =
    "git history keeps the OLD ciphertexts readable with the old key — \
full remediation also rotates the underlying secret values themselves";

#[derive(Debug)]
pub struct RotateOutcome {
    pub label: String,
    pub old_generation: Option<u16>,
    pub new_generation: u16,
    /// Repo files re-encrypted under the new key.
    pub reencrypted: Vec<String>,
    /// K3 documented caveat — the command's own output states it.
    pub caveat: &'static str,
}

/// Mint the next key generation and re-encrypt the project's ciphertexts
/// in the clone. With `--env` this rotates (or CREATES — K2) the
/// env-scoped key and touches only that environment; without it, the
/// project key rotates and every env still riding it is re-encrypted.
/// Push stays an explicit step.
pub fn rotate(p: &Platform, cwd: &str, env: Option<&str>) -> Result<RotateOutcome, LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    // D3a: rotation MUST run on fresh content. On a stale clone we would
    // re-encrypt outdated ciphertext and, after a forced push, resurrect
    // old secret values sealed under the new key — invisibly wrong.
    repo.refresh(true)?;
    let store = CredStore::new(p);

    // D2c: if the fresh repo already carries a generation at or above the
    // one we are about to mint, another machine rotated first. Minting
    // the same generation number with a different key would make its
    // files fail authentication and be reported as Corrupt. Refuse and
    // point at the fix: take that machine's key first.
    let current_gen = match env {
        Some(e) => keys::for_env(&store, &proj.name, e)?,
        None => keys::get(&store, &proj.name)?,
    }
    .map(|k| k.id.generation)
    .unwrap_or(0);
    let scan_envs: Vec<String> = match env {
        Some(e) => vec![e.to_string()],
        None => {
            let mut s = std::collections::BTreeSet::new();
            for rel in repo.list(&proj.name)? {
                if let Some((e, _)) = rel.split_once('/') {
                    s.insert(e.to_string());
                }
            }
            s.into_iter().collect()
        }
    };
    for e in &scan_envs {
        let prefix = format!("{}/{}", proj.name, e);
        for enc_name in repo.list(&prefix)? {
            if !enc_name.ends_with(".enc") {
                continue;
            }
            let enc_rel = format!("{}/{}", prefix, enc_name);
            if let Some(sealed) = repo.read(&enc_rel)? {
                if let Ok(id) = envelope::peek_key_id(&sealed, &enc_rel) {
                    if id.generation > current_gen {
                        return Err(LatchError::other(
                            format!(
                                "the repo already holds generation {} for '{}' — another machine rotated first",
                                id.generation, proj.name
                            ),
                            "take that machine's current key here (latch clone / latch key restore) before rotating again",
                        ));
                    }
                }
            }
        }
    }

    // B1: a leftover `#prev` means a previous rotation was interrupted
    // mid-re-encryption. RESUME it (finish sealing everything under the
    // current key) instead of minting yet another generation — that both
    // heals the mixed repo and avoids runaway generation numbers. Only a
    // clean state mints the next generation.
    let (old, new) = match keys::prev(&store, &proj.name, env)? {
        Some(prev) => {
            let cur = match env {
                Some(e) => keys::for_env(&store, &proj.name, e)?,
                None => keys::get(&store, &proj.name)?,
            }
            .ok_or_else(|| {
                LatchError::other(
                    "interrupted rotation with no current key",
                    "restore a key backup (latch key restore)",
                )
            })?;
            (Some(prev), cur)
        }
        None => keys::rotate(&store, &proj.name, env)?,
    };

    // Which environments do the new key's files live in?
    let envs: Vec<String> = match env {
        Some(e) => vec![e.to_string()],
        None => {
            // Every env under the project WITHOUT its own env key still
            // rides the project key and must be re-encrypted with it.
            let mut envs = std::collections::BTreeSet::new();
            for rel in repo.list(&proj.name)? {
                if let Some((e, _)) = rel.split_once('/') {
                    envs.insert(e.to_string());
                }
            }
            let mut out = Vec::new();
            for e in envs {
                let scoped = format!("key:{}", keys::label_for(&proj.name, Some(&e)));
                if store.get(&scoped)?.is_none() {
                    out.push(e);
                }
            }
            out
        }
    };

    // Try the current key first (already-rotated / resumed), then old —
    // so this is idempotent and a re-run finishes the job.
    let mut reencrypted = Vec::new();
    for e in &envs {
        let prefix = format!("{}/{}", proj.name, e);
        for enc_name in repo.list(&prefix)? {
            if !enc_name.ends_with(".enc") {
                continue;
            }
            let enc_rel = format!("{}/{}", prefix, enc_name);
            let Some(sealed) = repo.read(&enc_rel)? else {
                continue; // removed underneath us — skip (D6)
            };
            // Already at the new generation? Leave it (resume case).
            if envelope::open(&new.key, &new.id, &sealed, &enc_rel).is_ok() {
                continue;
            }
            let plain = old
                .as_ref()
                .and_then(|k| envelope::open(&k.key, &k.id, &sealed, &enc_rel).ok())
                .ok_or_else(|| {
                    LatchError::other(
                        format!("cannot re-encrypt {}: no key opens it", enc_rel),
                        "restore the old key first (latch key restore), then rotate",
                    )
                })?;
            let resealed = envelope::seal(&new.key, &new.id, &plain)?;
            repo.write(&enc_rel, &resealed)?;
            reencrypted.push(enc_rel);
        }
    }
    // Everything is now under the new key — the old generation can go.
    keys::clear_prev(&store, &proj.name, env)?;

    Ok(RotateOutcome {
        label: new.id.label.clone(),
        old_generation: old.map(|k| k.id.generation),
        new_generation: new.id.generation,
        reencrypted,
        caveat: ROTATE_CAVEAT,
    })
}

/// D2d: rotate a GROUP key (K3 for groups). Re-seals the group's stored
/// content under a fresh key generation; the cross-project blast-radius
/// keys were previously the only unrotatable ones. Push stays explicit.
pub fn rotate_group(p: &Platform, env: &str, name: &str) -> Result<RotateOutcome, LatchError> {
    crate::discovery::validate_env(env)?;
    let _lock = lock::acquire(p, 10, || {})?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    repo.refresh(true)?;
    let store = CredStore::new(p);

    let enc_rel = format!("_groups/{}/{}.enc", env, name);
    let sealed = repo.read(&enc_rel)?.ok_or_else(|| {
        LatchError::other(
            format!("group '{}' has no stored content for env '{}'", name, env),
            "commit a member with content first",
        )
    })?;

    let (old, new) = crate::groups::key_rotate(&store, name, env)?;
    // Open with the new key (resume case) or the old one, then re-seal.
    let plain = envelope::open(&new.key, &new.id, &sealed, &enc_rel)
        .or_else(|_| envelope::open(&old.key, &old.id, &sealed, &enc_rel))?;
    let resealed = envelope::seal(&new.key, &new.id, &plain)?;
    repo.write(&enc_rel, &resealed)?;
    crate::groups::key_clear_prev(&store, name, env)?;

    Ok(RotateOutcome {
        label: crate::groups::slot_for(name, env),
        old_generation: Some(old.id.generation),
        new_generation: new.id.generation,
        reencrypted: vec![enc_rel],
        caveat: ROTATE_CAVEAT,
    })
}

// ── K6 · latch key backup / restore ─────────────────────────────────────

const BACKUP_MAGIC: &[u8; 8] = b"LATCHBK1";
const BACKUP_LABEL: &str = "latch-backup";

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupPayload {
    repo: Option<String>,
    /// slot -> hex value (keys AND the pat — everything needed to stand
    /// up a machine from zero).
    slots: std::collections::BTreeMap<String, String>,
}

fn backup_passphrase(p: &Platform, confirm: bool) -> Result<String, LatchError> {
    if let Some(pp) = p.env.var("LATCH_BACKUP_PASSPHRASE") {
        return Ok(pp);
    }
    let pp = p.prompt.passphrase("backup passphrase")?;
    if confirm {
        let again = p.prompt.passphrase("repeat the backup passphrase")?;
        if pp != again {
            return Err(LatchError::other(
                "passphrases do not match",
                "run the backup again and type the same passphrase twice",
            ));
        }
    }
    Ok(pp)
}

/// Every slot this machine can enumerate: the pat, project + env keys for
/// configured projects (union of config and repo layout), group keys for
/// every group in the repo, plus whatever the file backend lists.
pub(crate) fn enumerate_slots(p: &Platform, store: &CredStore) -> Result<Vec<String>, LatchError> {
    let mut candidates: std::collections::BTreeSet<String> = ["pat".to_string()].into();
    let config = crate::config::Config::load(p)?;
    let mut envs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Ok(repo) = repo_handle(p) {
        if repo.ensure().is_ok() {
            for rel in repo.list("")? {
                let mut parts = rel.split('/');
                match (parts.next(), parts.next(), parts.next()) {
                    (Some("_groups"), Some(env), Some(name)) => {
                        if let Some(n) = name.strip_suffix(".enc") {
                            candidates.insert(format!("group:{}.{}", n, env));
                        }
                    }
                    (Some(project), Some(env), Some(_file)) => {
                        candidates.insert(format!("key:{}", project));
                        candidates.insert(format!("key:{}", keys::label_for(project, Some(env))));
                        envs.insert(env.to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    for proj in &config.projects {
        candidates.insert(format!("key:{}", proj.name));
        for e in &envs {
            candidates.insert(format!("key:{}", keys::label_for(&proj.name, Some(e))));
        }
    }
    for slot in store.file_slots()? {
        candidates.insert(slot);
    }
    // Keep only the slots that actually resolve to a value.
    let mut out = Vec::new();
    for slot in candidates {
        if store.get(&slot)?.is_some() {
            out.push(slot);
        }
    }
    Ok(out)
}

/// Like [`enumerate_slots`] but also returns the candidate slots that the
/// repo layout expects yet this machine does NOT hold (K1: a backup that
/// silently omits a key it can't see must SAY so, not report success as
/// if complete).
fn enumerate_with_skipped(
    p: &Platform,
    store: &CredStore,
) -> Result<(Vec<String>, Vec<String>), LatchError> {
    let mut candidates: std::collections::BTreeSet<String> = ["pat".to_string()].into();
    let config = crate::config::Config::load(p)?;
    let mut envs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Ok(repo) = repo_handle(p) {
        if repo.ensure().is_ok() {
            for rel in repo.list("")? {
                let mut parts = rel.split('/');
                match (parts.next(), parts.next(), parts.next()) {
                    (Some("_groups"), Some(env), Some(name)) => {
                        if let Some(n) = name.strip_suffix(".enc") {
                            candidates.insert(format!("group:{}.{}", n, env));
                        }
                    }
                    (Some(project), Some(env), Some(_file)) => {
                        candidates.insert(format!("key:{}", project));
                        candidates.insert(format!("key:{}", keys::label_for(project, Some(env))));
                        envs.insert(env.to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    for proj in &config.projects {
        candidates.insert(format!("key:{}", proj.name));
        for e in &envs {
            candidates.insert(format!("key:{}", keys::label_for(&proj.name, Some(e))));
        }
    }
    for slot in store.file_slots()? {
        candidates.insert(slot);
    }
    let mut held = Vec::new();
    let mut skipped = Vec::new();
    for slot in candidates {
        if store.get(&slot)?.is_some() {
            held.push(slot);
        } else {
            skipped.push(slot);
        }
    }
    Ok((held, skipped))
}

#[derive(Debug)]
pub struct BackupOutcome {
    pub path: String,
    pub slots: Vec<String>,
    /// Candidate slots the repo expects but this machine doesn't hold —
    /// the backup is complete only for what this machine can see (K1).
    pub skipped: Vec<String>,
    /// D13: key labels + generations whose escrow is now RECORDED in the
    /// secrets repo, so latch can see the second copy exists.
    pub recorded: Vec<(String, u16)>,
    /// The record is written into the LOCAL clone only. Publishing is an
    /// explicit act in latch (`latch push`), and pushing from here would
    /// sweep along whatever the user committed but deliberately has not
    /// pushed yet — `repo.push` stages the whole tree. So the record
    /// travels with the next push instead of surprising anyone.
    pub record_in_clone: bool,
}

/// K6: one passphrase-encrypted file holding every credential this
/// machine has — the "all machines lost" recovery path.
pub fn backup(p: &Platform, dest: &str) -> Result<BackupOutcome, LatchError> {
    let store = CredStore::new(p);
    let (slots, skipped) = enumerate_with_skipped(p, &store)?;
    if slots.is_empty() {
        return Err(LatchError::other(
            "nothing to back up — no credentials stored on this machine",
            "run 'latch login' and commit a project first",
        ));
    }
    let mut payload = BackupPayload {
        repo: crate::config::Config::load(p)?.repo,
        slots: Default::default(),
    };
    for slot in &slots {
        let (raw, _) = store.get(slot)?.expect("enumerated slot resolves");
        payload.slots.insert(slot.clone(), hex::encode(raw));
    }
    let plain = serde_json::to_vec(&payload).expect("payload serializes");

    let passphrase = backup_passphrase(p, true)?;
    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key = kdf::derive_key(&passphrase, &salt)?;
    let sealed = envelope::seal(&key, &KeyId::new(BACKUP_LABEL, 1)?, &plain)?;

    let mut out = Vec::with_capacity(BACKUP_MAGIC.len() + SALT_LEN + sealed.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&sealed);
    p.files.write_atomic(dest, &out)?;

    // D13: record THAT this escrow exists — in the repo, because the repo
    // is the one thing that survives losing this machine, which is the
    // failure being guarded against. Never key material: label,
    // generation, timestamp and the file's digest. Best-effort by design:
    // a backup asked for on an offline machine must still be made.
    let digest = crate::escrow::fingerprint(&out);
    let now = p.clock.now_unix();
    let mut recorded: Vec<(String, u16)> = Vec::new();
    let mut record_in_clone = false;
    if let Ok(repo) = repo_handle(p) {
        if repo.ensure().is_ok() {
            for slot in &slots {
                let Some(label) = slot.strip_prefix("key:") else {
                    continue;
                };
                // A rotation's previous generation is kept only to finish
                // re-encrypting; escrowing it would claim cover for a key
                // that is on its way out.
                if label.ends_with("#prev") {
                    continue;
                }
                let Some((raw, _)) = store.get(slot)? else {
                    continue;
                };
                if raw.len() < 2 {
                    continue;
                }
                let generation = u16::from_le_bytes([raw[0], raw[1]]);
                crate::escrow::note(&repo, label, generation, &digest, dest, now)?;
                recorded.push((label.to_string(), generation));
                record_in_clone = true;
            }
        }
    }
    Ok(BackupOutcome {
        path: dest.to_string(),
        slots,
        skipped,
        recorded,
        record_in_clone,
    })
}

#[derive(Debug)]
pub struct RestoreOutcome {
    pub restored: Vec<String>,
    pub repo_configured: bool,
}

/// K6: restore a backup file into this machine's credential store; sets
/// the repo in config when none is configured yet.
pub fn restore(p: &Platform, src: &str) -> Result<RestoreOutcome, LatchError> {
    let raw = p.files.read(src)?.ok_or_else(|| {
        LatchError::other(format!("backup file '{}' not found", src), "check the path")
    })?;
    if raw.len() < BACKUP_MAGIC.len() + SALT_LEN || &raw[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(LatchError::Format {
            context: src.into(),
            detail: "not a latch key backup file".into(),
        });
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[BACKUP_MAGIC.len()..BACKUP_MAGIC.len() + SALT_LEN]);
    let sealed = &raw[BACKUP_MAGIC.len() + SALT_LEN..];

    let passphrase = backup_passphrase(p, false)?;
    let key = kdf::derive_key(&passphrase, &salt)?;
    let plain = envelope::open(&key, &KeyId::new(BACKUP_LABEL, 1)?, sealed, src).map_err(|_| {
        LatchError::other(
            "backup cannot be opened — wrong passphrase or corrupted file",
            "check the passphrase; the file must be byte-identical to what 'latch key backup' wrote",
        )
    })?;
    let payload: BackupPayload =
        serde_json::from_slice(&plain).map_err(|e| LatchError::Format {
            context: src.into(),
            detail: format!("inner json: {}", e),
        })?;

    let store = CredStore::new(p);
    let mut restored = Vec::new();
    for (slot, hexed) in &payload.slots {
        let value = hex::decode(hexed).map_err(|_| LatchError::Format {
            context: format!("backup slot {}", slot),
            detail: "corrupt hex".into(),
        })?;
        store.set(slot, &value)?;
        restored.push(slot.clone());
    }
    let mut repo_configured = false;
    if let Some(repo) = payload.repo {
        let mut cfg = crate::config::Config::load(p)?;
        if cfg.repo.is_none() {
            cfg.repo = Some(repo);
            cfg.save(p)?;
            repo_configured = true;
        }
    }
    Ok(RestoreOutcome {
        restored,
        repo_configured,
    })
}
