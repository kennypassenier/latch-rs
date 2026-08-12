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

// ── L3: consumption & diagnosis on the same real-git world ─────────────

#[test]
fn l3_run_history_rollback_verify_state_reset() {
    use latch_core::ops::consume;

    let (tmp, origin) = scratch();
    let proj = tmp.path().join("work/app9");
    write(&proj.join(".env"), "TOKEN=first\nDEBUG=1\n");
    let m = Machine::new(tmp.path(), "home", &origin);
    let p = m.platform();
    init::run(&p, &proj.display().to_string(), None).unwrap();
    sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    sync::push(&p, &proj.display().to_string(), "dev", false).unwrap();

    // W6 run: secrets land in the child env, never on disk — proven with a
    // real child that checks the variable.
    let out = consume::run(
        &p,
        &proj.display().to_string(),
        "dev",
        "sh",
        &["-c", "test \"$TOKEN\" = first"],
    )
    .unwrap();
    assert_eq!(out.exit_code, 0, "child saw the injected TOKEN");
    assert_eq!(out.injected, 2);
    // And exit codes propagate.
    let out = consume::run(
        &p,
        &proj.display().to_string(),
        "dev",
        "sh",
        &["-c", "exit 7"],
    )
    .unwrap();
    assert_eq!(out.exit_code, 7);

    // Change + push a second version, then S3 history shows both.
    write(&proj.join(".env"), "TOKEN=second\nDEBUG=1\n");
    sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    sync::push(&p, &proj.display().to_string(), "dev", false).unwrap();
    let hist = consume::history(&p, &proj.display().to_string()).unwrap();
    assert!(hist.len() >= 2, "two pushes = two versions");

    // S3 rollback to the first version → push → pull → file restored.
    let first_ref = &hist.last().unwrap().reference;
    consume::rollback(&p, &proj.display().to_string(), "dev", first_ref).unwrap();
    sync::push(&p, &proj.display().to_string(), "dev", false).unwrap();
    sync::pull(&p, &proj.display().to_string(), "dev", false, true).unwrap();
    assert_eq!(
        std::fs::read_to_string(proj.join(".env")).unwrap(),
        "TOKEN=first\nDEBUG=1\n"
    );
    // Unknown ref is a clean error.
    let err = consume::rollback(&p, &proj.display().to_string(), "dev", "deadbeef").unwrap_err();
    assert!(format!("{err}").contains("latch history"), "{err}");

    // S6 verify: everything Ok. Then corrupt the file AT THE ORIGIN (via a
    // raw git clone — an attacker/bitrot scenario); verify refreshes and
    // must catch it.
    let ver = consume::verify(&p, None).unwrap();
    assert!(ver
        .entries
        .iter()
        .all(|(_, s)| *s == consume::VerifyState::Ok));
    let attacker = tmp.path().join("attacker");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&attacker)
        .status()
        .unwrap();
    let enc_path = attacker.join("app9/dev/.env.enc");
    let mut bytes = std::fs::read(&enc_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&enc_path, &bytes).unwrap();
    for args in [
        vec!["add", "-A"],
        vec![
            "-c",
            "user.email=a@b",
            "-c",
            "user.name=a",
            "commit",
            "-q",
            "-m",
            "tamper",
        ],
        vec!["push", "-q"],
    ] {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&attacker)
            .args(&args)
            .status()
            .unwrap();
    }
    let ver = consume::verify(&p, Some("app9")).unwrap();
    assert!(ver
        .entries
        .iter()
        .any(|(rel, s)| rel.contains(".env.enc") && *s == consume::VerifyState::Corrupt));

    // W8 state: the doctor sees the world.
    let st = consume::state(&p).unwrap();
    assert!(st.clone_exists);
    assert!(!st.keyring_available, "headless machine");
    assert!(st.cred_file, "file backend in use");
    assert_eq!(st.projects.len(), 1);
    assert!(st.projects[0].key.is_some());

    // W9 reset: clone gone, credentials stay; the re-clone still sees the
    // tampered origin (verify keeps reporting it — no false healing).
    consume::reset(&p, true).unwrap();
    let st = consume::state(&p).unwrap();
    assert!(!st.clone_exists);
    assert!(st.cred_file, "credentials survive reset");
    let ver = consume::verify(&p, Some("app9")).unwrap();
    assert!(
        ver.entries
            .iter()
            .any(|(_, s)| *s == consume::VerifyState::Corrupt),
        "tamper persists at origin"
    );

    // And the recovery story: S3 rollback to a good version fixes what S6
    // found — rollback, push, verify all-Ok.
    let hist = consume::history(&p, &proj.display().to_string()).unwrap();
    let good_ref = hist
        .iter()
        .find(|h| !h.message.contains("tamper"))
        .unwrap()
        .reference
        .clone();
    consume::rollback(&p, &proj.display().to_string(), "dev", &good_ref).unwrap();
    sync::push(&p, &proj.display().to_string(), "dev", false).unwrap();
    let ver = consume::verify(&p, Some("app9")).unwrap();
    assert!(
        ver.entries
            .iter()
            .all(|(_, s)| *s == consume::VerifyState::Ok),
        "rollback healed the corruption"
    );
}

// ── L4a: diff, edit, examples, templates-in-run ────────────────────────

#[test]
fn l4a_diff_edit_examples() {
    use latch_core::ops::edit_diff::{self, Change};

    let (tmp, origin) = scratch();
    let proj = tmp.path().join("work/app10");
    write(&proj.join(".env"), "KEEP=1\nCHANGE=old\nGONE=x\n");
    let m = Machine::new(tmp.path(), "home", &origin);
    let p = m.platform();
    init::run(&p, &proj.display().to_string(), None).unwrap();
    sync::commit(&p, &proj.display().to_string(), "dev").unwrap();
    sync::push(&p, &proj.display().to_string(), "dev", false).unwrap();

    // W10 diff, masked by default: names visible, values withheld.
    write(&proj.join(".env"), "KEEP=1\nCHANGE=new\nADDED=y\n");
    let d = edit_diff::diff(&p, &proj.display().to_string(), "dev", false).unwrap();
    assert_eq!(d.len(), 1);
    let entries = &d[0].entries;
    let find = |k: &str| entries.iter().find(|(n, ..)| n == k).unwrap();
    assert_eq!(find("CHANGE").1, Change::Changed);
    assert_eq!(find("ADDED").1, Change::Added);
    assert_eq!(find("GONE").1, Change::Removed);
    assert!(
        entries
            .iter()
            .all(|(_, _, old, new)| old.is_none() && new.is_none()),
        "masked by default"
    );
    let d = edit_diff::diff(&p, &proj.display().to_string(), "dev", true).unwrap();
    let ch = d[0].entries.iter().find(|(n, ..)| n == "CHANGE").unwrap();
    assert_eq!(ch.3.as_deref(), Some("new"), "--reveal shows values");

    // D3 examples: only via the explicit call; values provably absent.
    let written = edit_diff::write_examples(&p, &proj.display().to_string()).unwrap();
    assert_eq!(written, vec![".env.example".to_string()]);
    let example = std::fs::read_to_string(proj.join(".env.example")).unwrap();
    assert!(example.contains("ADDED=\n"));
    assert!(!example.contains("new"), "no values in examples");

    // W11 edit: "editor" is a script appending a var; tmp lives in the
    // runtime dir and is gone afterwards.
    let runtime = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let m2 = Machine::new(tmp.path(), "home", &origin); // same home
    let p2 = Platform {
        runtime_dir: Some(runtime.display().to_string()),
        ..m2.platform()
    };
    let editor = tmp.path().join("fake-editor.sh");
    std::fs::write(&editor, "#!/bin/sh\necho 'EDITED=yes' >> \"$1\"\n").unwrap();
    std::process::Command::new("chmod")
        .arg("+x")
        .arg(&editor)
        .status()
        .unwrap();
    m2.env.set("EDITOR", &editor.display().to_string());
    m2.env.set("LATCH_PASSPHRASE", "test-pp");
    let out =
        latch_core::ops::edit_diff::edit(&p2, &proj.display().to_string(), "dev", None).unwrap();
    assert!(out.changed);
    // Temp file cleaned up.
    assert!(
        std::fs::read_dir(&runtime).unwrap().next().is_none(),
        "no residue"
    );
    // The edit landed in the clone AND locally.
    assert!(std::fs::read_to_string(proj.join(".env"))
        .unwrap()
        .contains("EDITED=yes"));
    let st = sync::status(&p2, &proj.display().to_string(), "dev").unwrap();
    assert!(st.entries.iter().all(|(_, s)| *s == sync::FileState::Clean));

    // W7 in run: reference expands; typo fails naming the variable.
    write(&proj.join(".env"), "HOST=db1\nURL=pg://${HOST}/x\n");
    sync::commit(&p2, &proj.display().to_string(), "dev").unwrap();
    let out = latch_core::ops::consume::run(
        &p2,
        &proj.display().to_string(),
        "dev",
        "sh",
        &["-c", "test \"$URL\" = pg://db1/x"],
    )
    .unwrap();
    assert_eq!(out.exit_code, 0, "template expanded into the child env");
    write(&proj.join(".env"), "URL=pg://${TYPO}/x\n");
    sync::commit(&p2, &proj.display().to_string(), "dev").unwrap();
    let err = latch_core::ops::consume::run(&p2, &proj.display().to_string(), "dev", "true", &[])
        .unwrap_err();
    assert!(format!("{err}").contains("TYPO"), "{err}");
}

#[test]
fn s5_offline_cache_serves_when_origin_unreachable() {
    let (tmp, origin) = scratch();
    let proj = tmp.path().join("work-a/offapp");
    write(&proj.join(".env"), "TOKEN=cached\n");
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let cwd = proj.display().to_string();
    latch_core::ops::init::run(&pa, &cwd, None).unwrap();
    sync::commit(&pa, &cwd, "dev").unwrap();
    sync::push(&pa, &cwd, "dev", false).unwrap();

    // Simulate a network outage: the file:// origin stops existing.
    let bare = tmp.path().join("origin.git");
    let parked = tmp.path().join("origin.gone");
    std::fs::rename(&bare, &parked).unwrap();

    // W6/S5: run still injects from the cached clone, and REPORTS the
    // staleness instead of hiding it.
    let out_file = tmp.path().join("offline-run.txt");
    let cmd = format!("printf '%s' \"$TOKEN\" > {}", out_file.display());
    let run = latch_core::ops::consume::run(&pa, &cwd, "dev", "sh", &["-c", &cmd]).unwrap();
    assert_eq!(run.exit_code, 0);
    assert!(run.stale, "outage must surface as a stale notice");
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "cached");

    // Plain pull requires freshness and must FAIL LOUDLY, naming S5.
    let err = sync::pull(&pa, &cwd, "dev", false, true).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("cannot reach"), "{msg}");
    assert!(
        msg.contains("S5"),
        "the remedy points at offline mode: {msg}"
    );

    // pull --offline serves the cache and says so.
    std::fs::remove_file(proj.join(".env")).unwrap();
    let pulled = sync::pull(&pa, &cwd, "dev", true, true).unwrap();
    assert!(pulled.offline);
    assert_eq!(pulled.written, vec![".env"]);
    assert_eq!(
        std::fs::read_to_string(proj.join(".env")).unwrap(),
        "TOKEN=cached\n"
    );

    // Outage over: normal pull is fresh again.
    std::fs::rename(&parked, &bare).unwrap();
    let pulled = sync::pull(&pa, &cwd, "dev", false, true).unwrap();
    assert!(!pulled.offline);
}
