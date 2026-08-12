//! L1 tests: K4 resolution, AR3 file backend, AR11 TTL sessions, AR12
//! lock, M7 non-interactive hard errors, M1 login validation.

use latch_core::config::Config;
use latch_core::credentials::{env_var_for_slot, CredStore, Source};
use latch_core::error::LatchError;
use latch_core::lock;
use latch_core::ops::login;
use latch_core::platform::mock::*;
use latch_core::platform::Platform;

struct World {
    env: MockEnv,
    files: MockFiles,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
    proc: MockProc,
}

impl World {
    fn desktop() -> Self {
        Self {
            env: MockEnv::default(),
            files: MockFiles::default(),
            keyring: MockKeyring::default(),
            prompt: MockPrompt::default(),
            clock: MockClock::default(),
            proc: MockProc::default(),
        }
    }
    fn lxc() -> Self {
        Self {
            keyring: MockKeyring::headless(),
            ..Self::desktop()
        }
    }
    fn platform(&self) -> Platform<'_> {
        Platform {
            env: &self.env,
            files: &self.files,
            keyring: &self.keyring,
            prompt: &self.prompt,
            clock: &self.clock,
            proc: &self.proc,
            latch_home: "/home/t/.latch".into(),
            runtime_dir: Some("/run/user/1000/latch".into()),
        }
    }
}

#[test]
fn slot_env_names() {
    assert_eq!(env_var_for_slot("pat"), "LATCH_PAT");
    assert_eq!(
        env_var_for_slot("key:homelab.prod"),
        "LATCH_KEY_HOMELAB_PROD"
    );
    assert_eq!(
        env_var_for_slot("group:smtp-creds.dev"),
        "LATCH_GROUP_SMTP_CREDS_DEV"
    );
}

#[test]
fn k4_resolution_env_beats_file_beats_keyring() {
    let w = World::desktop();
    let p = w.platform();
    let store = CredStore::new(&p);
    // Keyring layer.
    w.keyring
        .slots
        .borrow_mut()
        .insert("pat".into(), b"from-keyring".to_vec());
    let (v, src) = store.get("pat").unwrap().unwrap();
    assert_eq!(
        (v.as_slice(), src),
        (b"from-keyring".as_slice(), Source::Keyring)
    );
    // File layer wins over keyring (headless-created file carried to a desktop).
    let lxc = World::lxc();
    lxc.env.set("LATCH_PASSPHRASE", "pp");
    let lp = lxc.platform();
    CredStore::new(&lp).set("pat", b"from-file").unwrap();
    let cred_file = lxc
        .files
        .files
        .borrow()
        .get("/home/t/.latch/credentials.enc")
        .cloned()
        .unwrap();
    w.files.seed("/home/t/.latch/credentials.enc", &cred_file);
    w.env.set("LATCH_PASSPHRASE", "pp");
    let (v, src) = store.get("pat").unwrap().unwrap();
    assert_eq!((v.as_slice(), src), (b"from-file".as_slice(), Source::File));
    // Env beats everything.
    w.env.set("LATCH_PAT", "from-env");
    let (v, src) = store.get("pat").unwrap().unwrap();
    assert_eq!(
        (v.as_slice(), src),
        (b"from-env".as_slice(), Source::EnvVar)
    );
}

#[test]
fn ar3_file_backend_round_trip_and_wrong_passphrase() {
    let w = World::lxc();
    w.env.set("LATCH_PASSPHRASE", "correct");
    let p = w.platform();
    let store = CredStore::new(&p);
    assert_eq!(store.set("key:homelab", b"k1").unwrap(), Source::File);
    let (v, src) = store.get("key:homelab").unwrap().unwrap();
    assert_eq!((v.as_slice(), src), (b"k1".as_slice(), Source::File));
    // Wrong passphrase → Integrity (indistinguishable from tampering, by design).
    let w2 = World::lxc();
    w2.files.seed(
        "/home/t/.latch/credentials.enc",
        &w.files
            .files
            .borrow()
            .get("/home/t/.latch/credentials.enc")
            .cloned()
            .unwrap(),
    );
    w2.env.set("LATCH_PASSPHRASE", "wrong");
    let p2 = w2.platform();
    let err = CredStore::new(&p2).get("key:homelab").unwrap_err();
    assert!(matches!(err, LatchError::Integrity { .. }), "{err}");
}

#[test]
fn ar11_session_cache_prompts_once_until_ttl_expires() {
    let w = World::lxc();
    let p = w.platform();
    let store = CredStore::new(&p);
    // First write: no env passphrase → prompt, cache session key.
    w.prompt.passphrases.borrow_mut().push("pp".into());
    store.set("pat", b"v").unwrap();
    assert_eq!(w.prompt.asked.borrow().len(), 1);
    w.files
        .set_mtime("/run/user/1000/latch/session.key", *w.clock.now.borrow());
    // Second op within TTL: session key used, NO prompt.
    store.get("pat").unwrap().unwrap();
    assert_eq!(
        w.prompt.asked.borrow().len(),
        1,
        "no second prompt within TTL"
    );
    // After TTL: prompt again.
    w.clock.advance(16 * 60);
    w.prompt.passphrases.borrow_mut().push("pp".into());
    store.get("pat").unwrap().unwrap();
    assert_eq!(
        w.prompt.asked.borrow().len(),
        2,
        "expired session re-prompts"
    );
}

#[test]
fn m7_headless_without_passphrase_is_a_hard_error_not_a_hang() {
    let w = World::lxc();
    let mut wp = w;
    wp.prompt = MockPrompt::non_interactive();
    let p = wp.platform();
    let err = CredStore::new(&p).set("pat", b"v").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("LATCH_"), "remedy names the env route: {msg}");
}

#[test]
fn ar12_lock_excludes_and_goes_stale() {
    let w = World::desktop();
    let p = w.platform();
    let guard = lock::acquire(&p, 0, || {}).unwrap();
    w.files
        .set_mtime("/home/t/.latch/lock", *w.clock.now.borrow());
    // Second acquire with zero wait: refused with remedy.
    let err = lock::acquire(&p, 0, || {}).unwrap_err();
    assert!(format!("{err}").contains("another latch operation"));
    drop(guard);
    // Lock released on drop → acquirable again.
    let _g = lock::acquire(&p, 0, || {}).unwrap();
    // Stale lock is broken: simulate a crashed process's old lock.
    drop(_g);
    let _ = p
        .files
        .try_create_exclusive("/home/t/.latch/lock", b"crashed");
    w.files
        .set_mtime("/home/t/.latch/lock", *w.clock.now.borrow());
    w.clock.advance(16 * 60);
    let _g2 = lock::acquire(&p, 0, || {}).unwrap();
}

#[test]
fn m1_login_validates_and_stores() {
    let w = World::desktop();
    let p = w.platform();
    let out = login::run(&p, Some("ghp_token".into()), Some("kenny/secrets".into())).unwrap();
    assert_eq!(out.repo, "kenny/secrets");
    assert_eq!(out.stored_in, Source::Keyring);
    // Validation ran a git ls-remote against the right URL…
    let calls = w.proc.calls_containing("ls-remote");
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("https://github.com/kenny/secrets.git"));
    // …and the token traveled via env, never argv.
    assert!(!calls[0].contains("ghp_token"));
    let envs = w.proc.env_log.borrow();
    assert!(envs[0]
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_VALUE_0" && v.contains("Basic ")));
    // Config recorded the repo.
    let cfg = Config::load(&p).unwrap();
    assert_eq!(cfg.repo.as_deref(), Some("kenny/secrets"));
}

#[test]
fn m1_login_bad_token_and_bad_repo_are_distinct() {
    let w = World::desktop();
    w.proc.respond(
        "ls-remote",
        128,
        b"",
        b"fatal: Authentication failed for url",
    );
    let p = w.platform();
    let err = login::run(&p, Some("bad".into()), Some("kenny/secrets".into())).unwrap_err();
    assert!(format!("{err}").contains("PAT"), "{err}");

    let w2 = World::desktop();
    w2.proc
        .respond("ls-remote", 128, b"", b"fatal: repository not found");
    let p2 = w2.platform();
    let err = login::run(&p2, Some("t".into()), Some("kenny/nope".into())).unwrap_err();
    assert!(format!("{err}").contains("not found"), "{err}");

    // Malformed repo name refused before any network.
    let w3 = World::desktop();
    let p3 = w3.platform();
    let err = login::run(&p3, Some("t".into()), Some("not-a-repo".into())).unwrap_err();
    assert!(format!("{err}").contains("owner/name"), "{err}");
    assert!(w3.proc.calls.borrow().is_empty());
}

#[test]
fn config_never_stores_secret_shaped_values() {
    let w = World::desktop();
    let p = w.platform();
    let mut cfg = Config::load(&p).unwrap();
    cfg.projects.push(latch_core::config::Project {
        name: "SECRET=hunter2\nOther".into(),
        dir: "/x".into(),
    });
    assert!(cfg.save(&p).is_err());
}
