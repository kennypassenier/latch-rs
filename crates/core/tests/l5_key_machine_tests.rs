//! L5 end-to-end: K2 per-env keys, K3 rotation, K5 show, K6 backup and
//! restore, M2 machine clone (manual verbs + the AR5 ssh wrapper).

use latch_core::config::Config;
use latch_core::envelope;
use latch_core::error::LatchError;
use latch_core::ops::{clone, consume, init, keyops, sync};
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockProc, MockPrompt};
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

fn scratch() -> (tempdir::TempDir, String) {
    let tmp = tempdir::TempDir::new("latch-l5").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let url = format!("file://{}", bare.display());
    (tmp, url)
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn k_series_rotation_env_keys_show_backup() {
    let (tmp, origin) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work-a/myapp");
    write(&proj.join(".env"), "TOKEN=dev-secret\n");
    let cwd = proj.display().to_string();
    init::run(&pa, &cwd, None).unwrap();

    // Same project, two environments.
    sync::commit(&pa, &cwd, "dev").unwrap();
    sync::push(&pa, &cwd, "dev", false).unwrap();
    write(&proj.join(".env"), "TOKEN=prod-secret\n");
    sync::commit(&pa, &cwd, "prod").unwrap();
    sync::push(&pa, &cwd, "prod", false).unwrap();

    // ── K5 · show hides by default, reveals only on demand ──────────────
    let info = keyops::show(&pa, &cwd, None, false).unwrap();
    assert_eq!(info.label, "myapp");
    assert_eq!(info.generation, 1);
    assert_eq!(info.env_var, "LATCH_KEY_MYAPP");
    assert!(info.hex.is_none(), "no key material without --reveal");
    let store = latch_core::credentials::CredStore::new(&pa);
    let (raw, _) = store.get("key:myapp").unwrap().unwrap();
    let info = keyops::show(&pa, &cwd, None, true).unwrap();
    assert_eq!(info.hex.unwrap(), hex::encode(&raw));

    // ── K3 · project rotation re-encrypts everything ────────────────────
    let old_key = latch_core::keys::get(&store, "myapp").unwrap().unwrap();
    let rot = keyops::rotate(&pa, &cwd, None).unwrap();
    assert_eq!(rot.old_generation, Some(1));
    assert_eq!(rot.new_generation, 2);
    assert_eq!(rot.reencrypted.len(), 2, "both envs rode the project key");
    assert!(rot.caveat.contains("history"), "K3 caveat in the output");
    sync::push(&pa, &cwd, "dev", false).unwrap();

    // New ciphertexts must REFUSE the old key (wrong generation).
    let repo_file = format!("{}/repo/myapp/dev/.env.enc", a.home);
    let sealed = std::fs::read(&repo_file).unwrap();
    let err = envelope::open(&old_key.key, &old_key.id, &sealed, ".env.enc").unwrap_err();
    assert!(
        matches!(err, LatchError::WrongKey { generation: 2, .. }),
        "{err}"
    );
    // And everything verifies with the current keys.
    let ver = consume::verify(&pa, None).unwrap();
    assert!(ver
        .entries
        .iter()
        .all(|(_, s)| matches!(s, consume::VerifyState::Ok)));

    // ── K2 · --env creates an isolated prod key ─────────────────────────
    let rot = keyops::rotate(&pa, &cwd, Some("prod")).unwrap();
    assert_eq!(rot.label, "myapp.prod");
    assert_eq!(rot.reencrypted, vec!["myapp/prod/.env.enc".to_string()]);
    sync::push(&pa, &cwd, "prod", false).unwrap();
    let ver = consume::verify(&pa, None).unwrap();
    assert!(ver
        .entries
        .iter()
        .all(|(_, s)| matches!(s, consume::VerifyState::Ok)));

    // Machine B holds ONLY the prod env key: prod decrypts, dev refuses
    // with a clear key-missing error — blast radius isolated (K2).
    let (prod_raw, _) = store.get("key:myapp.prod").unwrap().unwrap();
    let proj_b = tmp.path().join("work-b/myapp");
    std::fs::create_dir_all(&proj_b).unwrap();
    let b = Machine::new(tmp.path(), "home-b", &origin);
    b.env.set("LATCH_KEY_MYAPP_PROD", &hex::encode(&prod_raw));
    let pb = b.platform();
    let cwd_b = proj_b.display().to_string();
    init::run(&pb, &cwd_b, Some("myapp".into())).unwrap();
    let pulled = sync::pull(&pb, &cwd_b, "prod", false, false).unwrap();
    assert_eq!(pulled.written, vec![".env"]);
    assert_eq!(
        std::fs::read_to_string(proj_b.join(".env")).unwrap(),
        "TOKEN=prod-secret\n"
    );
    let err = sync::pull(&pb, &cwd_b, "dev", false, true).unwrap_err();
    assert!(
        format!("{err}").contains("not available here"),
        "dev must fail with a clear key-missing report: {err}"
    );

    // ── K6 · backup -> fresh machine -> restore -> everything works ─────
    let backup_file = tmp.path().join("keys.latchbk").display().to_string();
    a.env.set("LATCH_BACKUP_PASSPHRASE", "backup-pp");
    let bk = keyops::backup(&pa, &backup_file).unwrap();
    assert!(
        bk.slots.contains(&"key:myapp".to_string()),
        "{:?}",
        bk.slots
    );
    assert!(bk.slots.contains(&"key:myapp.prod".to_string()));
    let raw = std::fs::read(&backup_file).unwrap();
    assert!(raw.starts_with(b"LATCHBK1"));
    let hay = String::from_utf8_lossy(&raw);
    assert!(
        !hay.contains("myapp") && !hay.contains("prod-secret"),
        "backup leaks structure or content"
    );

    let c = Machine::new(tmp.path(), "home-c", &origin);
    c.env.set("LATCH_BACKUP_PASSPHRASE", "wrong-pp");
    let pc = c.platform();
    let err = keyops::restore(&pc, &backup_file).unwrap_err();
    assert!(format!("{err}").contains("passphrase"), "{err}");

    c.env.set("LATCH_BACKUP_PASSPHRASE", "backup-pp");
    let restored = keyops::restore(&pc, &backup_file).unwrap();
    assert!(restored.restored.contains(&"key:myapp".to_string()));
    let proj_c = tmp.path().join("work-c/myapp");
    std::fs::create_dir_all(&proj_c).unwrap();
    let cwd_c = proj_c.display().to_string();
    init::run(&pc, &cwd_c, Some("myapp".into())).unwrap();
    let pulled = sync::pull(&pc, &cwd_c, "dev", false, false).unwrap();
    assert_eq!(pulled.written, vec![".env"]);
}

#[test]
fn m2_clone_scoped_codes_and_expiry() {
    let (tmp, origin) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();

    // Source machine: two projects, so scope filtering is observable.
    let alpha = tmp.path().join("work-a/alpha");
    let beta = tmp.path().join("work-a/beta");
    write(&alpha.join(".env"), "ALPHA=1\n");
    write(&beta.join(".env"), "BETA=1\n");
    init::run(&pa, &alpha.display().to_string(), None).unwrap();
    init::run(&pa, &beta.display().to_string(), None).unwrap();
    sync::commit(&pa, &alpha.display().to_string(), "dev").unwrap();
    sync::push(&pa, &alpha.display().to_string(), "dev", false).unwrap();
    sync::commit(&pa, &beta.display().to_string(), "dev").unwrap();
    sync::push(&pa, &beta.display().to_string(), "dev", false).unwrap();

    // Target machine T (mock clock pinned to real time: offer TTL is
    // judged against the offer file's REAL mtime).
    let t = Machine::new(tmp.path(), "home-t", &origin);
    *t.clock.now.borrow_mut() = real_now();
    let pt = t.platform();
    let off = clone::offer(&pt).unwrap();
    assert!(off.offer.starts_with("LATCH-OFFER:"));

    // Scoped to alpha: beta's key must NOT travel.
    let created = clone::create(&pa, &off.offer, Some("alpha"), None).unwrap();
    assert!(created.slots.iter().any(|s| s == "key:alpha"));
    assert!(
        !created.slots.iter().any(|s| s.contains("beta")),
        "{:?}",
        created.slots
    );
    assert!(
        !created.payload.contains("alpha"),
        "payload is ciphertext, no structure visible"
    );

    // Right code: applied; repo configured; alpha pulls, beta has no key.
    let applied = clone::apply(&pt, &created.payload, Some(&created.code)).unwrap();
    assert!(applied.applied.contains(&"key:alpha".to_string()));
    let store_t = latch_core::credentials::CredStore::new(&pt);
    assert!(store_t.get("key:beta").unwrap().is_none(), "scope leaked");
    let alpha_t = tmp.path().join("work-t/alpha");
    std::fs::create_dir_all(&alpha_t).unwrap();
    init::run(&pt, &alpha_t.display().to_string(), Some("alpha".into())).unwrap();
    let pulled = sync::pull(&pt, &alpha_t.display().to_string(), "dev", false, false).unwrap();
    assert_eq!(pulled.written, vec![".env"]);

    // The offer is single-use: a second apply needs a fresh offer.
    let err = clone::apply(&pt, &created.payload, Some(&created.code)).unwrap_err();
    assert!(format!("{err}").contains("no pending"), "{err}");
    // (The wrong-code-burns-the-offer path is covered by
    // l8_hardening_tests::d5_wrong_code_consumes_the_offer.)

    // Expired offer: a fresh offer + a clock far in the future.
    let off2 = clone::offer(&pt).unwrap();
    let created2 = clone::create(&pa, &off2.offer, None, None).unwrap();
    t.clock.advance(16 * 60);
    let err = clone::apply(&pt, &created2.payload, Some(&created2.code)).unwrap_err();
    assert!(format!("{err}").contains("expired"), "{err}");
}

#[test]
fn m2_ssh_wrapper_drives_remote_verbs() {
    let (tmp, origin) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work-a/solo");
    write(&proj.join(".env"), "X=1\n");
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    sync::push(&pa, &proj.display().to_string(), "dev", false).unwrap();

    // A REAL target machine provides the offer; the wrapper's ssh calls
    // are mocked to hand that offer over and accept the apply.
    let t = Machine::new(tmp.path(), "home-t", &origin);
    *t.clock.now.borrow_mut() = real_now();
    let pt = t.platform();
    let off = clone::offer(&pt).unwrap();

    let proc = MockProc::default();
    proc.respond(
        "clone offer",
        0,
        format!("OFFER={}\n", off.offer).as_bytes(),
        b"",
    );
    proc.respond("clone apply", 0, b"APPLIED=2\n", b"");
    static FILES: RealFiles = RealFiles;
    let pw = Platform {
        env: &a.env,
        files: &FILES,
        keyring: &a.keyring,
        prompt: &a.prompt,
        clock: &a.clock,
        proc: &proc,
        latch_home: a.home.clone(),
        runtime_dir: None,
    };
    let out = clone::clone_to(&pw, "kenny@target", None, None).unwrap();
    assert_eq!(out.applied, 2);

    // The apply call carried the code and the sealed payload — replay it
    // against the real target machine to prove the transcript works.
    let calls = proc.calls_containing("clone apply");
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert!(call.contains(&format!("--code {}", out.code)), "{call}");
    let payload = call
        .split_whitespace()
        .find(|w| w.starts_with("LATCH-CLONE:"))
        .expect("payload travels as one argv token");
    let applied = clone::apply(&pt, payload, Some(&out.code)).unwrap();
    assert!(applied.applied.contains(&"key:solo".to_string()));
}
