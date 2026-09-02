//! D9: project removal + repo-wide listing, E2E against real git.
//! Chosen design (mini-round 2026-08-28): tiered scope (keys stay unless
//! purged), typed-name confirmation (headless needs --yes), history
//! untouched.

use latch_core::config::Config;
use latch_core::credentials::CredStore;
use latch_core::envelope;
use latch_core::ops::{consume, init, project, sync};
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

fn scratch() -> (tempdir::TempDir, String) {
    let tmp = tempdir::TempDir::new("latch-d9").unwrap();
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

/// Stand up two projects; `app` gets two envs so removal must sweep both.
fn seed(tmp: &tempdir::TempDir, origin: &str) -> (Machine, String, String) {
    let a = Machine::new(tmp.path(), "home-a", origin);
    let pa = a.platform();
    let app = tmp.path().join("work/app");
    let other = tmp.path().join("work/other");
    write(&app.join(".env"), "APP=dev-secret\n");
    write(&other.join(".env"), "OTHER=stays\n");
    init::run(&pa, &app.display().to_string(), None).unwrap();
    init::run(&pa, &other.display().to_string(), None).unwrap();
    sync::commit(&pa, &app.display().to_string(), "dev").unwrap();
    sync::push(&pa, &app.display().to_string(), "dev", false, true).unwrap();
    sync::commit(&pa, &app.display().to_string(), "prod").unwrap();
    sync::push(&pa, &app.display().to_string(), "prod", false, true).unwrap();
    sync::commit(&pa, &other.display().to_string(), "dev").unwrap();
    sync::push(&pa, &other.display().to_string(), "dev", false, true).unwrap();
    (a, app.display().to_string(), other.display().to_string())
}

#[test]
fn remove_sweeps_all_envs_keeps_keys_and_history() {
    let (tmp, origin) = scratch();
    let (a, _app_dir, _other_dir) = seed(&tmp, &origin);
    let pa = a.platform();

    // Typed-name confirmation (D9-C): the scripted line answers "app".
    a.prompt.lines.borrow_mut().push("app".into());
    let out = project::remove(&pa, "app", false, false).unwrap();
    assert_eq!(out.removed_files, 2, "dev + prod ciphertexts");
    assert_eq!(out.envs, vec!["dev".to_string(), "prod".to_string()]);
    assert!(out.was_linked);
    assert!(out.purged_keys.is_empty(), "keys stay by default (D9-B)");
    assert!(out.rotation_tip.contains("rotate"), "D9-D tip present");

    // Origin: app/ gone, other/ untouched — proven on a raw clone.
    let probe = tmp.path().join("probe");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(!probe.join("app").exists(), "app prefix must be gone");
    assert!(probe.join("other/dev/.env.enc").exists(), "other untouched");

    // Link + marker gone; key KEPT.
    assert!(project::list(&pa).unwrap().iter().all(|p| p.name != "app"));
    let store = CredStore::new(&pa);
    let key = latch_core::keys::get(&store, "app")
        .unwrap()
        .expect("key kept");

    // D9-D: history still opens with the kept key.
    let repo = consume::repo_handle(&pa).unwrap();
    let old = repo
        .read_at("HEAD^", "app/dev/.env.enc")
        .unwrap()
        .expect("history keeps the ciphertext");
    let plain = envelope::open(&key.key, &key.id, &old, "app/dev/.env.enc").unwrap();
    assert_eq!(plain, b"APP=dev-secret\n");

    // list_all no longer shows app; other still there and linked.
    let all = project::list_all(&pa).unwrap();
    assert!(all.iter().all(|p| p.name != "app"));
    assert!(all
        .iter()
        .any(|p| p.name == "other" && p.linked_dir.is_some()));
}

#[test]
fn wrong_name_refuses_and_headless_needs_yes() {
    let (tmp, origin) = scratch();
    let (a, _, _) = seed(&tmp, &origin);
    let pa = a.platform();

    // Wrong typed name → refusal, nothing changed at origin.
    a.prompt.lines.borrow_mut().push("appp".into());
    let err = project::remove(&pa, "app", false, false).unwrap_err();
    assert!(format!("{err}").contains("does not match"), "{err}");
    let probe = tmp.path().join("probe1");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(probe.join("app/dev/.env.enc").exists(), "nothing removed");

    // Headless without --yes → hard error naming the flag (M7).
    let b = Machine {
        prompt: MockPrompt::non_interactive(),
        ..Machine::new(tmp.path(), "home-b", &origin)
    };
    // home-b needs the key? remove doesn't decrypt — only listing/refresh.
    let pb = b.platform();
    let err = project::remove(&pb, "app", false, false).unwrap_err();
    assert!(format!("{err}").contains("--yes"), "{err}");

    // Headless WITH yes → succeeds.
    let out = project::remove(&pb, "app", true, false).unwrap();
    assert_eq!(out.removed_files, 2);
    assert!(!out.was_linked, "machine B never linked it");

    // Unknown project → clear error pointing at list/unbind.
    let err = project::remove(&pb, "app", true, false).unwrap_err();
    assert!(format!("{err}").contains("no project"), "{err}");
}

#[test]
fn purge_keys_empties_the_slots() {
    let (tmp, origin) = scratch();
    let (a, _, _) = seed(&tmp, &origin);
    let pa = a.platform();
    let store = CredStore::new(&pa);
    assert!(store.get("key:app").unwrap().is_some());

    a.prompt.lines.borrow_mut().push("app".into());
    let out = project::remove(&pa, "app", false, true).unwrap();
    assert!(
        out.purged_keys.contains(&"key:app".to_string()),
        "{:?}",
        out.purged_keys
    );
    assert!(store.get("key:app").unwrap().is_none(), "slot emptied");
}
