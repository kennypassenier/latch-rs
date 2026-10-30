//! Master-passphrase login (2026-10-30): keys wrapped in the secrets repo,
//! one env file per machine, and a migration that may lose nothing.
//! E2E against real git on scratch repos with invented secrets only.

use latch_core::config::Config;
use latch_core::credentials::{env_var_for_slot, CredStore, Source};
use latch_core::envfile;
use latch_core::keywrap;
use latch_core::ops::master_login::{self, Options};
use latch_core::ops::{consume, init, sync};
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockPrompt};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Platform;

struct Machine {
    home: String,
    env: MockEnv,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
}

impl Machine {
    fn new(base: &std::path::Path, name: &str, origin: &str) -> Self {
        let env = MockEnv::default();
        env.set("LATCH_PASSPHRASE", "test-pp");
        let m = Self {
            home: base.join(name).display().to_string(),
            env,
            keyring: MockKeyring::headless(),
            prompt: MockPrompt::default(),
            clock: MockClock::default(),
        };
        let p = m.platform();
        let mut cfg = Config::load(&p).unwrap();
        cfg.repo = Some(origin.to_string());
        cfg.save(&p).unwrap();
        m
    }
    fn platform(&self) -> Platform<'_> {
        static FILES: RealFiles = RealFiles;
        static PROC: RealProc = RealProc;
        Platform {
            env: &self.env,
            files: &FILES,
            keyring: &self.keyring,
            prompt: &self.prompt,
            clock: &self.clock,
            proc: &PROC,
            latch_home: self.home.clone(),
            runtime_dir: None,
        }
    }
    fn file(&self, rel: &str) -> std::path::PathBuf {
        std::path::Path::new(&self.home).join(rel)
    }
}

fn scratch() -> (tempdir::TempDir, String) {
    let tmp = tempdir::TempDir::new("latch-master").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    (tmp, format!("file://{}", bare.display()))
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// Machine "home" with two projects committed and pushed. Returns the
/// machine and the project directories.
fn seeded(tmp: &tempdir::TempDir, origin: &str) -> (Machine, String, String) {
    let a = Machine::new(tmp.path(), "home", origin);
    let pa = a.platform();
    let one = tmp.path().join("work/app").display().to_string();
    let two = tmp.path().join("work/site").display().to_string();
    write(
        std::path::Path::new(&one).join(".env").as_path(),
        "TOKEN=invented-one\n",
    );
    write(
        std::path::Path::new(&two).join(".env").as_path(),
        "TOKEN=invented-two\n",
    );
    for dir in [&one, &two] {
        init::run(&pa, dir, None).unwrap();
        sync::commit(&pa, dir, "dev").unwrap();
    }
    sync::push(&pa, &one, "dev", false, false).unwrap();
    sync::push(&pa, &two, "dev", false, false).unwrap();
    (a, one, two)
}

fn clone_origin(tmp: &tempdir::TempDir, origin: &str, name: &str) -> std::path::PathBuf {
    let dir = tmp.path().join(name);
    std::process::Command::new("git")
        .args(["clone", "-q", origin])
        .arg(&dir)
        .status()
        .unwrap();
    dir
}

const PASS: &str = "k7q4-mx2d-9wfa-hh3t-bn6c-ze";

#[test]
fn migration_wraps_every_key_proves_every_file_and_touches_nothing_old() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();

    let cipher_before =
        std::fs::read(clone_origin(&tmp, &origin, "p1").join("app/dev/.env.enc")).unwrap();
    let cred_before = std::fs::read(a.file("credentials.enc")).unwrap();
    let key_before = std::fs::read(a.file("credentials.key")).ok();

    let prep = master_login::prepare(&pa).unwrap();
    assert!(!prep.initialised);
    assert_eq!(
        prep.held,
        vec!["key:app".to_string(), "key:site".to_string()]
    );
    assert_eq!(prep.inspection.opened(), 2);
    // prepare is read-only: no snapshot yet
    assert!(!a.file("migration-snapshots").exists());

    let out = master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();
    assert_eq!(
        out.wrapped,
        vec!["key:app".to_string(), "key:site".to_string()]
    );
    assert_eq!(out.files_proven, 2);
    assert!(out.published);

    // the old store is byte for byte what it was
    assert_eq!(
        std::fs::read(a.file("credentials.enc")).unwrap(),
        cred_before
    );
    assert_eq!(std::fs::read(a.file("credentials.key")).ok(), key_before);
    // a snapshot of it exists
    assert!(std::path::Path::new(&out.snapshot)
        .join("credentials.enc")
        .exists());
    // the env file now holds both keys
    let env = envfile::read_all(&pa).unwrap();
    assert!(env.contains_key(&env_var_for_slot("key:app")));
    assert!(env.contains_key(&env_var_for_slot("key:site")));

    // the repo: wraps and salt are new, existing ciphertext is untouched
    let probe = clone_origin(&tmp, &origin, "p2");
    assert!(probe.join("_keywrap/salt").exists());
    assert!(probe.join("_keywrap/key~app.g1.wrap").exists());
    assert_eq!(
        std::fs::read(probe.join("app/dev/.env.enc")).unwrap(),
        cipher_before
    );
    // and no key material is readable in the repo
    let wrap_bytes = std::fs::read(probe.join("_keywrap/key~app.g1.wrap")).unwrap();
    let raw_key = CredStore::new(&pa).get("key:app").unwrap().unwrap().0;
    assert!(!wrap_bytes
        .windows(raw_key.len())
        .any(|w| w == raw_key.as_slice()));
    assert!(!String::from_utf8_lossy(&wrap_bytes).contains(PASS));
}

#[test]
fn a_new_machine_needs_only_the_repo_and_the_passphrase() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();
    let prep = master_login::prepare(&pa).unwrap();
    master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();

    // machine B: nothing but the repo setting
    let b = Machine::new(tmp.path(), "laptop", &origin);
    let pb = b.platform();
    let prep_b = master_login::prepare(&pb).unwrap();
    assert!(prep_b.initialised);
    assert!(prep_b.held.is_empty());
    // typed with capitals, spaces and without dashes: same passphrase
    let typed = "K7Q4 MX2D 9WFA HH3T BN6C ZE";
    let out = master_login::apply(&pb, &prep_b, typed, Options::default()).unwrap();
    assert_eq!(
        out.imported,
        vec!["key:app".to_string(), "key:site".to_string()]
    );
    assert!(out.wrapped.is_empty());
    assert!(!out.published);

    // login + pull is enough: the project decrypts on the new machine
    let work = tmp.path().join("laptop-work/app").display().to_string();
    write(std::path::Path::new(&work).join(".env").as_path(), "");
    let mut cfg = Config::load(&pb).unwrap();
    cfg.projects.push(latch_core::config::Project {
        name: "app".into(),
        dir: work.clone(),
    });
    cfg.save(&pb).unwrap();
    std::fs::remove_file(std::path::Path::new(&work).join(".env")).unwrap();
    sync::pull(&pb, &work, "dev", false, true).unwrap();
    assert_eq!(
        std::fs::read_to_string(std::path::Path::new(&work).join(".env")).unwrap(),
        "TOKEN=invented-one\n"
    );
    // and a service could load the env file alone
    let env = envfile::read_all(&pb).unwrap();
    assert!(env.contains_key(&env_var_for_slot("key:app")));
}

#[test]
fn a_wrong_passphrase_changes_nothing_anywhere() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();
    let prep = master_login::prepare(&pa).unwrap();
    master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();

    let b = Machine::new(tmp.path(), "laptop", &origin);
    let pb = b.platform();
    let prep_b = master_login::prepare(&pb).unwrap();
    let err = master_login::apply(
        &pb,
        &prep_b,
        "not-the-right-passphrase-at-all",
        Options::default(),
    )
    .unwrap_err();
    assert!(
        format!("{err}").contains("does not open the key wraps"),
        "{err}"
    );
    assert!(!b.file("latch.env").exists());
    assert!(!b.file("credentials.enc").exists());
    assert!(!b.file("migration-snapshots").exists());
}

#[test]
fn a_failed_proof_restores_the_old_store_exactly() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();

    // Corrupt one ciphertext in the origin: it cannot open through ANY
    // store, so the proof must fail and everything must roll back.
    let work = clone_origin(&tmp, &origin, "tamper");
    let target = work.join("site/dev/.env.enc");
    let mut bytes = std::fs::read(&target).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&target, bytes).unwrap();
    for args in [
        vec!["add", "-A"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "tamper",
        ],
        vec!["push", "-q", "origin", "HEAD:main"],
    ] {
        std::process::Command::new("git")
            .current_dir(&work)
            .args(args)
            .status()
            .unwrap();
    }

    let cred_before = std::fs::read(a.file("credentials.enc")).unwrap();
    // seeding mirrored the keys into the env file already; it must come back as it was
    let env_before = std::fs::read(a.file("latch.env")).unwrap();
    let prep = master_login::prepare(&pa).unwrap();
    assert_eq!(prep.inspection.failures().len(), 1);
    let err = master_login::apply(&pa, &prep, PASS, Options::default()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("migration proof failed"), "{msg}");
    assert!(msg.contains("everything was rolled back"), "{msg}");

    assert_eq!(
        std::fs::read(a.file("latch.env")).unwrap(),
        env_before,
        "env file restored"
    );
    assert_eq!(
        std::fs::read(a.file("credentials.enc")).unwrap(),
        cred_before
    );
    // nothing was published
    assert!(!clone_origin(&tmp, &origin, "after")
        .join("_keywrap")
        .exists());
}

#[test]
fn a_key_the_repo_needs_but_nobody_holds_stops_unless_allowed() {
    let (tmp, origin) = scratch();
    let (_a, _one, _two) = seeded(&tmp, &origin);

    // machine C holds no keys and the repo has no wraps yet
    let c = Machine::new(tmp.path(), "stranger", &origin);
    let pc = c.platform();
    let prep = master_login::prepare(&pc).unwrap();
    assert!(prep.missing.contains("key:app"));
    let err = master_login::apply(&pc, &prep, PASS, Options::default()).unwrap_err();
    assert!(format!("{err}").contains("key:app"), "{err}");
    assert!(!c.file("latch.env").exists());

    let out = master_login::apply(
        &pc,
        &prep,
        PASS,
        Options {
            allow_missing: true,
        },
    )
    .unwrap();
    assert!(out.wrapped.is_empty());
    assert_eq!(out.files_proven, 0);
}

#[test]
fn running_it_twice_changes_nothing_the_second_time() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();
    let prep = master_login::prepare(&pa).unwrap();
    master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();

    let prep2 = master_login::prepare(&pa).unwrap();
    assert!(prep2.initialised);
    let out = master_login::apply(&pa, &prep2, PASS, Options::default()).unwrap();
    assert!(out.wrapped.is_empty());
    assert!(!out.published);
    assert_eq!(out.files_proven, 2);
}

#[test]
fn a_rotated_key_is_rewrapped_and_the_old_generation_pruned() {
    let (tmp, origin) = scratch();
    let (a, one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();
    let prep = master_login::prepare(&pa).unwrap();
    master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();

    latch_core::ops::keyops::rotate(&pa, &one, None).unwrap();
    sync::push(&pa, &one, "dev", false, false).unwrap();
    // the rotated generation is uncovered until it is wrapped
    assert!(latch_core::ops::cover::warning(&pa, "app", "dev")
        .unwrap()
        .is_some());

    let prep2 = master_login::prepare(&pa).unwrap();
    let out = master_login::apply(&pa, &prep2, PASS, Options::default()).unwrap();
    assert_eq!(out.wrapped, vec!["key:app".to_string()]);
    assert!(latch_core::ops::cover::warning(&pa, "app", "dev")
        .unwrap()
        .is_none());
    let probe = clone_origin(&tmp, &origin, "rot");
    assert!(probe.join("_keywrap/key~app.g2.wrap").exists());
    assert!(!probe.join("_keywrap/key~app.g1.wrap").exists());
    let st = consume::state(&pa).unwrap();
    assert_eq!(
        st.projects
            .iter()
            .find(|p| p.name == "app")
            .unwrap()
            .wrapped,
        Some(true)
    );
}

#[test]
fn the_env_file_mirrors_writes_and_serves_a_machine_that_has_only_it() {
    let (tmp, origin) = scratch();
    let m = Machine::new(tmp.path(), "solo", &origin);
    let p = m.platform();
    let store = CredStore::new(&p);
    store.set("pat", b"ghp_invented").unwrap();
    // every set is mirrored; both stores agree, the older file answers
    let (v, src) = store.get("pat").unwrap().unwrap();
    assert_eq!(
        (v.as_slice(), src),
        (b"ghp_invented".as_slice(), Source::File)
    );
    assert!(std::fs::read_to_string(m.file("latch.env"))
        .unwrap()
        .contains("LATCH_PAT=ghp_invented"));
    // a service host has only the env file: it answers
    std::fs::remove_file(m.file("credentials.enc")).unwrap();
    let (v, src) = store.get("pat").unwrap().unwrap();
    assert_eq!(
        (v.as_slice(), src),
        (b"ghp_invented".as_slice(), Source::EnvFile)
    );
    // an environment variable still wins over both
    m.env.set("LATCH_PAT", "from-env");
    assert_eq!(store.get("pat").unwrap().unwrap().1, Source::EnvVar);
}

#[test]
fn env_file_parsing_refuses_what_it_cannot_read() {
    assert!(envfile::parse(b"NOT A VARIABLE LINE\n").is_err());
    assert!(envfile::parse(b"1BAD=x\n").is_err());
    let ok = envfile::parse(b"# c\n\nLATCH_PAT=\"quoted\"\nLATCH_KEY_X=ab12\n").unwrap();
    assert_eq!(ok["LATCH_PAT"], "quoted");
    assert_eq!(ok["LATCH_KEY_X"], "ab12");
}

#[test]
fn generated_passphrases_are_long_random_and_survive_pasting() {
    let a = keywrap::generate_passphrase();
    let b = keywrap::generate_passphrase();
    assert_eq!(a.len(), 26);
    assert_ne!(a, b);
    assert!(keywrap::check_strength(&a).is_ok());
    assert_eq!(keywrap::normalize(&keywrap::display(&a)), a);
    assert_eq!(
        keywrap::normalize(&keywrap::display(&a).to_uppercase().replace('-', " ")),
        a
    );
    assert!(keywrap::check_strength("too-short-for-this").is_err());
}

#[test]
fn v1_leftovers_in_the_repo_are_reported_and_never_block_the_migration() {
    let (tmp, origin) = scratch();
    let (a, _one, _two) = seeded(&tmp, &origin);
    let pa = a.platform();

    // a file that was never a v2 envelope, as the real repo holds ten of
    let work = clone_origin(&tmp, &origin, "legacy");
    write(
        &work.join("old/dev/leftover.env.enc"),
        "not an envelope at all",
    );
    for args in [
        vec!["add", "-A"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "legacy",
        ],
        vec!["push", "-q", "origin", "HEAD:main"],
    ] {
        std::process::Command::new("git")
            .current_dir(&work)
            .args(args)
            .status()
            .unwrap();
    }

    let prep = master_login::prepare(&pa).unwrap();
    assert_eq!(
        prep.inspection.not_v2(),
        vec!["old/dev/leftover.env.enc".to_string()]
    );
    assert!(prep.inspection.failures().is_empty());
    let out = master_login::apply(&pa, &prep, PASS, Options::default()).unwrap();
    assert_eq!(out.files_proven, 2);
    let probe = clone_origin(&tmp, &origin, "legacy-after");
    assert_eq!(
        std::fs::read_to_string(probe.join("old/dev/leftover.env.enc")).unwrap(),
        "not an envelope at all"
    );
}
