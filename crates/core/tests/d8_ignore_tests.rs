//! D8 · `.latchignore` and the discovery walk (amends D1).
//!
//! Live bug, 2026-08-28 (found consuming latch from the almanac project):
//! discovery honoured `.gitignore`, so it skipped exactly the files it
//! exists to manage — every project lists `.env` there. `latch commit`
//! reported "0 file(s)" and called it success.
//!
//! These tests run against the REAL filesystem and REAL git (standing
//! rule 9): the mock file backend has no notion of ignore files, which is
//! precisely why ~90 green tests never saw this.

use latch_core::discovery;
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockPrompt};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Files;
use latch_core::platform::Platform;

fn git_init(dir: &std::path::Path) {
    std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(dir)
        .status()
        .expect("git init");
}

fn write(path: &std::path::Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn found(dir: &std::path::Path) -> Vec<String> {
    discovery::discover(&RealFiles, &dir.display().to_string()).unwrap()
}

/// The reported bug: `.env` in `.gitignore` is the norm, not a signal to
/// skip the file. Discovery must find it anyway.
#[test]
fn gitignored_env_files_are_still_discovered() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    git_init(root);
    write(&root.join(".gitignore"), ".env\n*.env\n");
    write(&root.join(".env"), "A=1\n");
    write(&root.join(".env.local"), "B=1\n");
    write(&root.join("api/.env"), "C=1\n");
    write(&root.join(".env.example"), "A=\n");

    assert_eq!(found(root), vec![".env", ".env.local", "api/.env"]);
}

/// A monorepo subproject: the ignore rule lives one directory up, in a
/// repo the project directory does not even own.
#[test]
fn a_parent_repos_gitignore_cannot_hide_env_files() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    git_init(tmp.path());
    write(&tmp.path().join(".gitignore"), ".env\n");
    let root = tmp.path().join("services/api");
    write(&root.join(".env"), "A=1\n");

    assert_eq!(found(&root), vec![".env"]);
}

/// `.latchignore` is latch's own exclusion file, gitignore format.
#[test]
fn latchignore_excludes_what_it_names() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    write(&root.join(".latchignore"), "fixtures/\n.env.local\n");
    write(&root.join(".env"), "A=1\n");
    write(&root.join(".env.local"), "B=1\n");
    write(&root.join("fixtures/.env"), "C=1\n");

    assert_eq!(found(root), vec![".env"]);
}

/// Dependency directories are skipped without anyone writing a rule —
/// otherwise the first commit in a Node project offers dozens of stray
/// `.env` files from third-party packages.
#[test]
fn dependency_directories_are_pruned_by_default() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    write(&root.join(".env"), "A=1\n");
    for dir in [
        ".git",
        "node_modules/pkg",
        "target/debug",
        "vendor",
        ".venv",
        "venv",
        ".latch",
    ] {
        write(&root.join(dir).join(".env"), "X=1\n");
    }

    assert_eq!(found(root), vec![".env"]);
}

/// The built-in list is a floor, not a cage: an explicit negation in the
/// project-root `.latchignore` lifts it.
#[test]
fn a_negation_lifts_a_built_in_exclusion() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    write(&root.join(".latchignore"), "!vendor/\n");
    write(&root.join(".env"), "A=1\n");
    write(&root.join("vendor/.env"), "B=1\n");
    write(&root.join("node_modules/pkg/.env"), "C=1\n");

    assert_eq!(found(root), vec![".env", "vendor/.env"]);
}

/// v1 treated `.env.sample` as a template like `.env.example`; v2 lost
/// that and would encrypt it as a secret.
#[test]
fn env_sample_is_a_template_not_a_secret() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    write(&root.join(".env"), "A=1\n");
    write(&root.join(".env.sample"), "A=\n");
    write(&root.join(".env.example"), "A=\n");

    assert_eq!(found(root), vec![".env"]);
}

/// The `--no-ignore` diagnostic answers "what are the rules hiding?",
/// which is the question nobody could answer during the live incident.
#[test]
fn discover_all_lifts_every_exclusion() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    write(&root.join(".latchignore"), "fixtures/\n");
    write(&root.join(".env"), "A=1\n");
    write(&root.join("fixtures/.env"), "B=1\n");
    write(&root.join("node_modules/pkg/.env"), "C=1\n");

    let all = discovery::discover_all(&RealFiles, &root.display().to_string()).unwrap();
    assert_eq!(all, vec![".env", "fixtures/.env", "node_modules/pkg/.env"]);
    // The rules themselves are unchanged — this is a view, not a mode.
    assert_eq!(found(root), vec![".env"]);
}

/// The secrets clone is latch's own storage: a stray ignore file there
/// must never be able to hide a ciphertext from a pull.
#[test]
fn the_secrets_clone_listing_is_never_filtered() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let root = tmp.path();
    git_init(root);
    write(&root.join(".gitignore"), "*.enc\n");
    write(&root.join(".latchignore"), "*.enc\n");
    write(&root.join("demo/dev/.env.enc"), "ciphertext");

    let listed = RealFiles.walk_all(&root.display().to_string()).unwrap();
    assert!(
        listed.contains(&"demo/dev/.env.enc".to_string()),
        "ciphertext must survive any ignore file: {listed:?}"
    );
}

/// `latch init` leaves a starter `.latchignore` behind, so the mechanism
/// is discoverable in the project itself rather than only in the guide.
#[test]
fn init_leaves_a_starter_latchignore() {
    let tmp = tempdir::TempDir::new("latch-d8").unwrap();
    let home = tmp.path().join("home").display().to_string();
    let dir = tmp.path().join("work");
    std::fs::create_dir_all(&dir).unwrap();
    let env = MockEnv::default();
    env.set("LATCH_PASSPHRASE", "test-pp");
    static FILES: RealFiles = RealFiles;
    static PROC: RealProc = RealProc;
    let keyring = MockKeyring::headless();
    let prompt = MockPrompt::default();
    let clock = MockClock::default();
    let p = Platform {
        env: &env,
        files: &FILES,
        keyring: &keyring,
        prompt: &prompt,
        clock: &clock,
        proc: &PROC,
        latch_home: home,
        runtime_dir: None,
    };

    latch_core::ops::init::run(&p, &dir.display().to_string(), Some("demo".into())).unwrap();

    let written = std::fs::read_to_string(dir.join(".latchignore")).expect(".latchignore written");
    assert!(
        written.contains("node_modules"),
        "the starter file documents the built-in list: {written}"
    );

    // Idempotent: a second init never overwrites the user's own rules.
    std::fs::write(dir.join(".latchignore"), "mine\n").unwrap();
    latch_core::ops::init::run(&p, &dir.display().to_string(), Some("demo".into())).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join(".latchignore")).unwrap(),
        "mine\n"
    );
}
