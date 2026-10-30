//! `latch login --master`: the terminal side of the master-passphrase
//! flow. All decisions and all writes live in
//! `latch_core::ops::master_login`; this file only shows what is about to
//! happen and asks for the passphrase.

use latch_core::config::Config;
use latch_core::credentials::CredStore;
use latch_core::error::LatchError;
use latch_core::keywrap;
use latch_core::ops::master_login::{self, Options};
use latch_core::platform::Platform;

const ENV_PASSPHRASE: &str = "LATCH_MASTER_PASSPHRASE";

pub fn run(
    p: &Platform,
    pat: Option<String>,
    repo: Option<String>,
    dry_run: bool,
    allow_missing: bool,
) -> Result<(), LatchError> {
    let logged_in = Config::load(p)?.repo.is_some() && CredStore::new(p).get("pat")?.is_some();
    if pat.is_some() || repo.is_some() || !logged_in {
        if dry_run {
            return Err(LatchError::other(
                "--dry-run needs a machine that is already logged in",
                "run 'latch login --master' without --dry-run first",
            ));
        }
        let out = latch_core::ops::login::run(p, pat, repo)?;
        println!("✓ repo {} verified, token stored", out.repo);
    }

    let prep = master_login::prepare(p)?;
    println!("keys held on this machine : {}", prep.held.len());
    for (project, (opened, total)) in prep.inspection.per_project() {
        println!(
            "  {:16} {} of {} files open with a key held here",
            project, opened, total
        );
    }
    for slot in &prep.missing {
        println!("  needs a key this machine does not hold: {}", slot);
    }
    println!(
        "master passphrase in the repo : {}",
        if prep.initialised {
            "set"
        } else {
            "not set yet"
        }
    );
    let legacy = prep.inspection.not_v2();
    if !legacy.is_empty() {
        println!(
            "  {} files in the repo are not in the v2 format (v1 leftovers, never readable by v2, left untouched)",
            legacy.len()
        );
    }
    for (file, why) in prep.inspection.failures() {
        println!("  FAILS TO OPEN: {} ({})", file, why);
    }
    if dry_run {
        println!("dry run: nothing was written");
        return Ok(());
    }

    let passphrase = passphrase(p, prep.initialised)?;
    let out = master_login::apply(p, &prep, &passphrase, Options { allow_missing })?;
    println!("✓ snapshot of the old store kept in {}", out.snapshot);
    for slot in &out.imported {
        println!("  imported from the repo: {}", slot);
    }
    for slot in &out.wrapped {
        println!("  wrapped under the master passphrase: {}", slot);
    }
    println!(
        "✓ proven: {} files open to identical plaintext through {}",
        out.files_proven,
        latch_core::envfile::path(p)
    );
    if out.published {
        println!("✓ key wraps published and read back from the repo");
    } else {
        println!("✓ key wraps already in the repo, read back and equal");
    }
    Ok(())
}

/// The passphrase for this run: the environment wins (scripts), else a
/// generated one is shown once and must be confirmed saved, else the
/// existing one is asked for.
fn passphrase(p: &Platform, initialised: bool) -> Result<String, LatchError> {
    if let Some(v) = p.env.var(ENV_PASSPHRASE) {
        return Ok(v);
    }
    if initialised {
        return p.prompt.passphrase("master passphrase");
    }
    let fresh = keywrap::generate_passphrase();
    println!();
    println!("Your new master passphrase (shown once, store it in your password manager now):");
    println!();
    println!("    {}", keywrap::display(&fresh));
    println!();
    if !p.prompt.confirm("Is it saved in your password manager?")? {
        return Err(LatchError::other(
            "stopped before anything was written",
            "run 'latch login --master' again for a new passphrase",
        ));
    }
    Ok(fresh)
}
