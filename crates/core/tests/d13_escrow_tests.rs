//! D13: latch must know whether a second copy of a key exists, and must
//! refuse to publish secrets under a key that has none. Mini-round
//! 2026-09-02, after a system upgrade wiped the KDE keyring and took
//! every key with it — the keyring had been the only copy, and nothing
//! in latch had any concept of a backup existing.
//!
//! E2E against real git, because the record lives in the secrets repo
//! (the one thing that survives losing the machine).

use latch_core::config::Config;
use latch_core::escrow::{self, EscrowStatus, FileState};
use latch_core::ops::{consume, init, keyops, project, sync};
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
        env.set("LATCH_BACKUP_PASSPHRASE", "escrow-pp");
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
    let tmp = tempdir::TempDir::new("latch-d13").unwrap();
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

fn seed(tmp: &tempdir::TempDir, origin: &str) -> (Machine, String) {
    let a = Machine::new(tmp.path(), "home", origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/app");
    write(&proj.join(".env"), "TOKEN=only-copy-secret\n");
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    (a, proj.display().to_string())
}

#[test]
fn push_refuses_under_a_key_with_no_recorded_backup() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();

    // The whole point: publishing puts ciphertext in a place this machine
    // can lose the only key to. Without a recorded escrow, refuse.
    let err = sync::push(&pa, &proj, "dev", false, false).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("no key backup is recorded"), "{msg}");
    assert!(msg.contains("app"), "names the key: {msg}");
    assert!(msg.contains("latch key backup"), "remedy first: {msg}");
    assert!(msg.contains("--no-escrow"), "escape named: {msg}");

    // Nothing reached the origin.
    let probe = tmp.path().join("probe");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(
        !probe.join("app/dev/.env.enc").exists(),
        "nothing published"
    );

    // Taking the backup records it, and the same push then goes through.
    let escrow_file = tmp.path().join("escrow.latchbk");
    let out = keyops::backup(&pa, &escrow_file.display().to_string()).unwrap();
    assert!(
        out.recorded.iter().any(|(l, g)| l == "app" && *g == 1),
        "backup records the escrow: {:?}",
        out.recorded
    );
    sync::push(&pa, &proj, "dev", false, false).unwrap();

    // The record is in the REPO — it has to survive losing this machine.
    let repo = consume::repo_handle(&pa).unwrap();
    let raw = repo
        .read("_escrow/app.json")
        .unwrap()
        .expect("record lives in the repo");
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("file_sha256"), "{text}");
    // And it carries no key material or passphrase — it is a note, not a
    // second hiding place (standing rule 10).
    assert!(!text.contains("only-copy-secret"), "{text}");
    assert!(!text.contains("escrow-pp"), "{text}");
    assert!(!text.contains("test-pp"), "{text}");

    // state tells the story, including that the file is still there.
    let st = consume::state(&pa).unwrap();
    let app = st.projects.iter().find(|p| p.name == "app").unwrap();
    match app.escrow.as_ref().expect("escrow known") {
        EscrowStatus::Recorded {
            generation, file, ..
        } => {
            assert_eq!(*generation, 1);
            assert_eq!(*file, FileState::Matches);
        }
        other => panic!("expected a recorded escrow, got {other:?}"),
    }
}

#[test]
fn no_escrow_publishes_but_the_choice_stays_visible() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();

    // The agreed fallback: an exception is allowed, but never invisible.
    sync::push(&pa, &proj, "dev", false, true).unwrap();
    let st = consume::state(&pa).unwrap();
    let app = st.projects.iter().find(|p| p.name == "app").unwrap();
    assert!(
        matches!(
            app.escrow.as_ref().unwrap(),
            EscrowStatus::SkippedOnPurpose { generation: 1, .. }
        ),
        "{:?}",
        app.escrow
    );

    // A later push needs no new decision — the skip is already recorded.
    write(
        std::path::Path::new(&proj).join(".env").as_path(),
        "TOKEN=second\n",
    );
    sync::commit(&pa, &proj, "dev").unwrap();
    sync::push(&pa, &proj, "dev", false, false).unwrap_err();

    // Taking the backup replaces the skip with a real escrow.
    let escrow_file = tmp.path().join("escrow.latchbk");
    keyops::backup(&pa, &escrow_file.display().to_string()).unwrap();
    sync::push(&pa, &proj, "dev", false, false).unwrap();
    let st = consume::state(&pa).unwrap();
    let app = st.projects.iter().find(|p| p.name == "app").unwrap();
    assert!(matches!(
        app.escrow.as_ref().unwrap(),
        EscrowStatus::Recorded { generation: 1, .. }
    ));
}

#[test]
fn a_rotated_key_needs_its_own_escrow() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();
    let escrow_file = tmp.path().join("escrow.latchbk");
    keyops::backup(&pa, &escrow_file.display().to_string()).unwrap();
    sync::push(&pa, &proj, "dev", false, false).unwrap();

    // K3 rotation mints generation 2; the old escrow cannot open what the
    // new key seals, so it does not count as cover for it.
    keyops::rotate(&pa, &proj, None).unwrap();
    let repo = consume::repo_handle(&pa).unwrap();
    assert!(escrow::has(&repo, "app", 1).unwrap());
    assert!(!escrow::has(&repo, "app", 2).unwrap());
    let err = sync::push(&pa, &proj, "dev", false, false).unwrap_err();
    assert!(format!("{err}").contains("generation 2"), "{err}");

    keyops::backup(&pa, &escrow_file.display().to_string()).unwrap();
    sync::push(&pa, &proj, "dev", false, false).unwrap();
}

#[test]
fn remove_only_warns_about_history_when_a_key_can_still_read_it() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();
    let escrow_file = tmp.path().join("escrow.latchbk");
    keyops::backup(&pa, &escrow_file.display().to_string()).unwrap();
    sync::push(&pa, &proj, "dev", false, false).unwrap();

    // Reported by the homelab session, 2026-09-02: removing a project
    // whose key is gone printed the rotate-your-values warning, which
    // urges work that would fix nothing. Keys kept → the warning is true.
    // A v1-era artifact sitting at the project root, exactly as the real
    // repository still had one.
    let repo_pre = consume::repo_handle(&pa).unwrap();
    repo_pre
        .write("app/manifest.json", b"{\"v1\":true}")
        .unwrap();

    a.prompt.lines.borrow_mut().push("app".into());
    let out = project::remove(&pa, "app", false, false).unwrap();
    assert!(out.rotation_tip.contains("rotate the underlying VALUES"));

    // The whole project prefix goes, including anything that is not a
    // ciphertext: v1 left a `manifest.json` at the project root, and the
    // filter that derives environments used to skip it, so a removed
    // project stayed half-present on disk (homelab session, 2026-09-02).
    let repo = consume::repo_handle(&pa).unwrap();
    assert!(
        repo.read("app/manifest.json").unwrap().is_none(),
        "a v1 leftover must not survive the removal"
    );

    // Same command with the keys purged: the history is unreadable for
    // everyone here, so the honest note says exactly that.
    let (tmp2, origin2) = scratch();
    let (b, proj2) = seed(&tmp2, &origin2);
    let pb = b.platform();
    let escrow2 = tmp2.path().join("escrow.latchbk");
    keyops::backup(&pb, &escrow2.display().to_string()).unwrap();
    sync::push(&pb, &proj2, "dev", false, false).unwrap();
    let out = project::remove(&pb, "app", true, true).unwrap();
    assert!(
        out.rotation_tip.contains("cannot be opened by anyone here"),
        "{}",
        out.rotation_tip
    );
    assert!(!out.purged_keys.is_empty());
}

#[test]
fn a_stored_value_that_is_not_a_key_says_so() {
    let (tmp, origin) = scratch();
    let (a, _proj) = seed(&tmp, &origin);
    let pa = a.platform();
    let store = latch_core::credentials::CredStore::new(&pa);

    // The trap the Almanac session hit while recovering: the env-var form
    // of a key is 68 hex characters, the stored form is 34 raw bytes.
    // Writing the hex into the slot used to read back as "key MISSING",
    // indistinguishable from having stored nothing at all — which sends
    // someone hunting for a key that is sitting right there.
    let hex_form = "01".repeat(34);
    store.set("key:app", hex_form.as_bytes()).unwrap();

    let st = consume::state(&pa).unwrap();
    let app = st.projects.iter().find(|p| p.name == "app").unwrap();
    assert!(app.key.is_none());
    assert_eq!(
        app.key_unreadable_bytes,
        Some(68),
        "state must report a stored-but-unreadable value, not MISSING"
    );
}
