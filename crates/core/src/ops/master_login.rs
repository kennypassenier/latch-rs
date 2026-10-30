//! `latch login --master`: put the machine's keys under ONE master
//! passphrase in the secrets repo, and/or bring those keys onto a machine
//! that has none. Split in two so a shell can ask the right question in
//! between: [`prepare`] reads only; [`apply`] writes, with the safety net
//! of `migrate` (snapshot, proof, rollback) around every write.
//!
//! The order inside [`apply`] is the migration contract:
//!  1. clone is clean and current (nothing of the user's gets swept along)
//!  2. master key from the passphrase; existing wraps opened with it
//!  3. a wrap that disagrees with a local key stops everything
//!  4. snapshot, then import missing keys, then write the env file
//!  5. PROOF: every ciphertext that opened before opens to identical
//!     plaintext through the env file alone
//!  6. wrap + publish only what is missing, then re-fetch and compare
//!
//! Any failure restores the snapshot and discards the clone's changes.

use std::collections::BTreeSet;

use crate::credentials::{encode_env_value, env_var_for_slot, is_binary_slot, CredStore};
use crate::error::LatchError;
use crate::keywrap;
use crate::lock;
use crate::ops::keyops::enumerate_with_skipped;
use crate::ops::migrate::{self, Inspection};
use crate::ops::sync::repo_handle;
use crate::platform::Platform;
use crate::repo::{PushOutcome, RefreshState};

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Continue although some ciphertexts need keys this machine (and the
    /// repo's wraps) do not hold. They stay closed; they are listed.
    pub allow_missing: bool,
}

/// Everything `--dry-run` shows; nothing has been written.
#[derive(Debug)]
pub struct Prepared {
    /// A master passphrase already exists in the repo.
    pub initialised: bool,
    /// Key and group slots this machine holds (no PAT, no rotation leftovers).
    pub held: Vec<String>,
    /// Slots the repo's ciphertexts need that this machine lacks.
    pub missing: BTreeSet<String>,
    pub inspection: Inspection,
}

#[derive(Debug)]
pub struct Outcome {
    pub snapshot: String,
    pub imported: Vec<String>,
    pub wrapped: Vec<String>,
    pub files_proven: usize,
    pub published: bool,
}

pub fn prepare(p: &Platform) -> Result<Prepared, LatchError> {
    let repo = repo_handle(p)?;
    repo.ensure()?;
    require_clean(repo.refresh(true)?)?;
    let store = CredStore::new(p);
    let inspection = migrate::inspect(&repo, &migrate::chain_source(&store))?;
    Ok(Prepared {
        initialised: keywrap::is_initialised(&repo)?,
        held: held_binary_slots(p, &store)?,
        missing: inspection.missing_slots(),
        inspection,
    })
}

pub fn apply(
    p: &Platform,
    prep: &Prepared,
    passphrase: &str,
    opts: Options,
) -> Result<Outcome, LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let canonical = keywrap::normalize(passphrase);
    if !prep.initialised {
        keywrap::check_strength(&canonical)?;
    }
    let repo = repo_handle(p)?;
    repo.ensure()?;
    require_clean(repo.refresh(true)?)?;
    // The clone is clean here, so any early failure below (which may have
    // written the salt into it) is undone by simply matching the remote.
    apply_checked(p, &repo, prep, &canonical, opts).inspect_err(|_| {
        let _ = repo.discard_local();
    })
}

fn apply_checked(
    p: &Platform,
    repo: &crate::repo::Repo,
    prep: &Prepared,
    canonical: &str,
    opts: Options,
) -> Result<Outcome, LatchError> {
    let store = CredStore::new(p);

    let master = keywrap::master_key(repo, canonical, !prep.initialised)?;
    let remote = if prep.initialised {
        keywrap::unwrap_all(repo, &master).map_err(|e| match e {
            LatchError::Integrity { .. } => LatchError::other(
                "the master passphrase does not open the key wraps in the secrets repo",
                "check the passphrase in your password manager (dashes and capitals do not matter); nothing was changed",
            ),
            other => other,
        })?
    } else {
        Default::default()
    };

    // Same generation must be the same key. A newer local generation is a
    // rotation this machine did (it gets wrapped below); a newer wrap means
    // another machine rotated first. Neither is resolved by guessing.
    for (slot, wrapped) in &remote {
        let Some((local, _)) = store.get(slot)? else {
            continue;
        };
        let (lg, rg) = (
            keywrap::generation_of(&local),
            keywrap::generation_of(wrapped),
        );
        let conflict = match (lg, rg) {
            (Some(l), Some(r)) if l == r => local != *wrapped,
            (Some(l), Some(r)) => l < r,
            _ => true,
        };
        if conflict {
            return Err(LatchError::other(
                format!("{} differs between this machine and the key wrap in the repo", slot),
                "nothing was changed; compare both machines before continuing (latch key show), then ask for help rather than overwriting either",
            ));
        }
    }

    let before = migrate::inspect(repo, &migrate::chain_source(&store))?;
    let uncovered: BTreeSet<String> = before
        .missing_slots()
        .into_iter()
        .filter(|s| !remote.contains_key(s))
        .collect();
    if !uncovered.is_empty() && !opts.allow_missing {
        return Err(LatchError::other(
            format!(
                "the repo holds ciphertexts for keys this machine does not have: {}",
                uncovered.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
            "nothing was changed; run latch login --master --dry-run to see them, restore the keys (latch key restore) or pass --allow-missing to leave those files closed",
        ));
    }

    let snapshot = migrate::take_snapshot(p)?;
    let result = write_and_prove(p, repo, &store, &master, &remote, &before, &uncovered);
    match result {
        Ok(mut outcome) => {
            outcome.snapshot = snapshot.dir;
            Ok(outcome)
        }
        Err(e) => {
            let restored = migrate::restore_snapshot(p, &snapshot);
            let discarded = repo.discard_local();
            let tail = match (restored, discarded) {
                (Ok(()), Ok(())) => format!(
                    "everything was rolled back; the snapshot stays in {}",
                    snapshot.dir
                ),
                (r, d) => format!(
                    "ROLLBACK INCOMPLETE ({:?} / {:?}); restore by hand from {}",
                    r.err().map(|e| e.to_string()),
                    d.err().map(|e| e.to_string()),
                    snapshot.dir
                ),
            };
            Err(LatchError::other(
                format!("{} — {}", e, tail),
                "nothing was lost; fix the cause and run it again",
            ))
        }
    }
}

fn write_and_prove(
    p: &Platform,
    repo: &crate::repo::Repo,
    store: &CredStore,
    master: &[u8; crate::envelope::KEY_LEN],
    remote: &std::collections::BTreeMap<String, Vec<u8>>,
    before: &Inspection,
    allowed_missing: &BTreeSet<String>,
) -> Result<Outcome, LatchError> {
    // 4. import what the repo has and this machine lacks
    let mut imported = Vec::new();
    for (slot, raw) in remote {
        if store.get(slot)?.is_none() {
            store.set(slot, raw)?;
            imported.push(slot.clone());
        }
    }
    // the env file gets every held slot, in one write
    let mut env = crate::envfile::read_all(p)?;
    for slot in all_held_slots(p, store)? {
        if let Some((raw, _)) = store.get(&slot)? {
            env.insert(env_var_for_slot(&slot), encode_env_value(&slot, &raw));
        }
    }
    crate::envfile::write_all(p, &env)?;

    // 5. the proof, through the env file ALONE
    let after = migrate::inspect(repo, &migrate::env_file_source(p))?;
    let problems = migrate::compare(before, &after, allowed_missing);
    if !problems.is_empty() {
        return Err(LatchError::other(
            format!("migration proof failed: {}", problems.join("; ")),
            "the old store is untouched",
        ));
    }

    // 6. wrap what is missing, publish, re-fetch, compare
    let held = held_binary_slots(p, store)?;
    let mut wrapped = Vec::new();
    for slot in &held {
        let (raw, _) = store.get(slot)?.expect("held slot resolves");
        let generation = keywrap::generation_of(&raw).ok_or_else(|| {
            LatchError::other(
                format!("{} is not a generation-prefixed key", slot),
                "run latch state",
            )
        })?;
        if !keywrap::has_wrap(repo, slot, generation)? {
            keywrap::wrap(repo, master, slot, &raw)?;
            wrapped.push(slot.clone());
        }
    }
    let published = matches!(
        repo.push("add key wraps (latch login --master)", false)?,
        PushOutcome::Pushed
    );
    require_clean_after(repo.refresh(true)?)?;
    let check = keywrap::unwrap_all(repo, master)?;
    for slot in &held {
        let (raw, _) = store.get(slot)?.expect("held slot resolves");
        if check.get(slot) != Some(&raw) {
            return Err(LatchError::other(
                format!(
                    "the key wrap for {} read back from the repo does not match",
                    slot
                ),
                "the wraps already published are harmless ciphertext; the local store is restored",
            ));
        }
    }
    Ok(Outcome {
        snapshot: String::new(),
        imported,
        wrapped,
        files_proven: after.opened(),
        published,
    })
}

fn require_clean(state: RefreshState) -> Result<(), LatchError> {
    if state.is_current() {
        return Ok(());
    }
    Err(LatchError::other(
        "the local clone of the secrets repo has changes the remote has not seen",
        "run 'latch push' (or 'latch reset') first so nothing of yours is swept into the key wraps, then run this again",
    ))
}

fn require_clean_after(state: RefreshState) -> Result<(), LatchError> {
    if state.is_current() {
        return Ok(());
    }
    Err(LatchError::other(
        "could not re-read the secrets repo after publishing the key wraps",
        "the wraps were pushed; run this again to verify them",
    ))
}

/// Key and group slots only, without rotation leftovers (`#prev`).
fn held_binary_slots(p: &Platform, store: &CredStore) -> Result<Vec<String>, LatchError> {
    Ok(enumerate_with_skipped(p, store)?
        .0
        .into_iter()
        .filter(|s| is_binary_slot(s) && !s.contains('#'))
        .collect())
}

/// Every slot for the env file: the PAT too. Rotation leftovers stay in
/// the encrypted file only.
fn all_held_slots(p: &Platform, store: &CredStore) -> Result<Vec<String>, LatchError> {
    Ok(enumerate_with_skipped(p, store)?
        .0
        .into_iter()
        .filter(|s| crate::credentials::mirrors_to_env_file(s))
        .collect())
}
