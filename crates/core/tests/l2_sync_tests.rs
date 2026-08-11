//! L2 end-to-end: the real sync loop with the REAL git binary against a
//! local bare repository (file:// origin) — the milestone exit. Real
//! files, real subprocesses; keyring mocked headless so the credential
//! file backend is exercised too.

use latch_core::config::Config;
use latch_core::error::LatchError;
use latch_core::ops::{init, sync};
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
        let home = base.join(name).display().to_string();
        let env = MockEnv::default();
        env.set("LATCH_PASSPHRASE", "test-pp");
        let m = Self {
            home,
            env,
            keyring: MockKeyring::headless(),
            prompt: MockPrompt::default(),
            clock: MockClock::default(),
        };
        // Configure the repo (normally done by latch login).
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
}

fn scratch() -> (tempdir::TempDir, String) {
    let tmp = tempdir::TempDir::new("latch-l2").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let url = format!("file://{}", bare.display());
    (tmp, url)
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn full_round_trip_and_second_machine() {
    let (tmp, origin) = scratch();
    let proj_a = tmp.path().join("work-a/myapp");
    write(&proj_a.join(".env"), "TOP=1\n");
    write(&proj_a.join("api/.env"), "API_KEY=abc\n");
    write(&proj_a.join(".env.example"), "TOP=\n"); // must be ignored (D1)

    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();

    // init + commit + push on machine A.
    let out = init::run(&pa, &proj_a.display().to_string(), None).unwrap();
    assert_eq!(out.project, "myapp");
    assert!(out.created_key);
    let commit = sync::commit(&pa, &proj_a.display().to_string(), "dev").unwrap();
    let names: Vec<_> = commit.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec![".env", "api/.env"],
        "example excluded, list visible"
    );
    assert!(matches!(
        sync::push(&pa, &proj_a.display().to_string(), "dev", false).unwrap(),
        latch_core::repo::PushOutcome::Pushed
    ));

    // The origin now holds ONLY ciphertext (A5): clone it raw and scan.
    let probe = tmp.path().join("probe");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&probe)
        .status()
        .unwrap();
    let enc = std::fs::read(probe.join("myapp/dev/api__.env.enc")).unwrap();
    assert!(enc.starts_with(b"LATCH2"));
    let hay = String::from_utf8_lossy(&enc);
    assert!(!hay.contains("API_KEY"), "plaintext never reaches the repo");

    // Machine B: fresh home, key transferred via env injection (K4).
    let proj_b = tmp.path().join("work-b/myapp");
    std::fs::create_dir_all(&proj_b).unwrap();
    let b = Machine::new(tmp.path(), "home-b", &origin);
    // Move the key: read from A's store, inject into B's env (hex of 34B).
    let store_a = latch_core::credentials::CredStore::new(&pa);
    let (raw_key, _) = store_a.get("key:myapp").unwrap().unwrap();
    // The K4 orchestrator scenario: the key arrives as a hex env var
    // (exactly how the homelab host vault would inject it).
    b.env.set("LATCH_KEY_MYAPP", &hex::encode(&raw_key));
    let pb = b.platform();
    init::run(&pb, &proj_b.display().to_string(), Some("myapp".into())).unwrap();
    let pulled = sync::pull(&pb, &proj_b.display().to_string(), "dev", false, false).unwrap();
    assert_eq!(pulled.written.len(), 2);
    assert_eq!(
        std::fs::read_to_string(proj_b.join("api/.env")).unwrap(),
        "API_KEY=abc\n"
    );

    // Status on B: everything clean.
    let st = sync::status(&pb, &proj_b.display().to_string(), "dev").unwrap();
    assert!(st.entries.iter().all(|(_, s)| *s == sync::FileState::Clean));

    // B modifies + pushes; A's un-pulled push must then be refused (S4).
    write(&proj_b.join("api/.env"), "API_KEY=rotated\n");
    sync::commit(&pb, &proj_b.display().to_string(), "dev").unwrap();
    sync::push(&pb, &proj_b.display().to_string(), "dev", false).unwrap();

    write(&proj_a.join(".env"), "TOP=2\n");
    sync::commit(&pa, &proj_a.display().to_string(), "dev").unwrap();
    let err = sync::push(&pa, &proj_a.display().to_string(), "dev", false).unwrap_err();
    assert!(format!("{err}").contains("S4"), "{err}");
    // Force takes A's content on top — no force-push, history intact.
    sync::push(&pa, &proj_a.display().to_string(), "dev", true).unwrap();

    // Pull on A with local mods: S4 refusal without overwrite.
    // (B rotated api/.env remotely… but A force-pushed after commit of
    // both files, so A is current. Modify A locally against the clone:)
    write(&proj_a.join("api/.env"), "API_KEY=local-edit\n");
    let err = sync::pull(&pa, &proj_a.display().to_string(), "dev", false, false).unwrap_err();
    assert!(format!("{err}").contains("overwritten"), "{err}");
    let pulled = sync::pull(&pa, &proj_a.display().to_string(), "dev", false, true).unwrap();
    assert!(pulled.written.contains(&"api/.env".to_string()));
}

#[test]
fn commit_is_idempotent_and_detects_removals() {
    let (tmp, origin) = scratch();
    let proj = tmp.path().join("work/app2");
    write(&proj.join(".env"), "A=1\n");
    let m = Machine::new(tmp.path(), "home", &origin);
    let p = m.platform();
    init::run(&p, &proj.display().to_string(), None).unwrap();

    let first = sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    assert!(first.files.iter().all(|(_, changed)| *changed));
    // Second commit without edits: nothing changed (no-op re-encryption
    // would pollute git history).
    let second = sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    assert!(second.files.iter().all(|(_, changed)| !*changed));
    // Removing the local file removes the intent at next commit.
    std::fs::remove_file(proj.join(".env")).unwrap();
    let third = sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    assert_eq!(third.removed, vec![".env".to_string()]);
}

#[test]
fn unlinked_dir_is_guided_to_init() {
    let (tmp, origin) = scratch();
    let m = Machine::new(tmp.path(), "home", &origin);
    let p = m.platform();
    let err = sync::commit(&p, "/nowhere/special", "dev").unwrap_err();
    assert!(format!("{err}").contains("latch init"), "{err}");
}

#[test]
fn wrong_key_on_pull_reports_what_is_needed() {
    let (tmp, origin) = scratch();
    let proj = tmp.path().join("work/app3");
    write(&proj.join(".env"), "S=1\n");
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    sync::push(&pa, &proj.display().to_string(), "dev", false).unwrap();

    // Machine B gets a DIFFERENT key for the same project name.
    let proj_b = tmp.path().join("work-b/app3");
    std::fs::create_dir_all(&proj_b).unwrap();
    let b = Machine::new(tmp.path(), "home-b", &origin);
    let pb = b.platform();
    init::run(&pb, &proj_b.display().to_string(), Some("app3".into())).unwrap();
    let err = sync::pull(&pb, &proj_b.display().to_string(), "dev", false, false).unwrap_err();
    match err {
        LatchError::Integrity { .. } => {} // same label+gen, different bytes
        LatchError::WrongKey { .. } => {}
        other => panic!("expected key error, got {other}"),
    }
}
