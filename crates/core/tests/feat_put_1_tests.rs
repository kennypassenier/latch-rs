//! feat-put-1: replace ONE file of ONE environment without a pull and
//! without touching the others. Asked for by the homelab dashboard
//! (homelab-admin on CT 120), decided by Kenny on 2026-09-28
//! ("latch krijgt een commando voor één bestand"). The trap it avoids:
//! `latch commit` on a machine that holds only some of a project's files
//! records every other file as removed and refuses only when ALL would
//! go — the shape of the 17-file wipe of 2026-09-20. E2E against real git.

use latch_core::config::Config;
use latch_core::ops::{consume, init, put, sync};
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockPrompt};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Platform;
use sha2::{Digest, Sha256};

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
            prompt: MockPrompt::non_interactive(),
            clock: MockClock::default(),
        };
        let p = m.platform();
        let mut cfg = Config::load(&p).unwrap();
        cfg.repo = Some(origin.to_string());
        cfg.save(&p).unwrap();
        m
    }
    /// A second machine holding the same credentials, like the dashboard
    /// with its own copy: same passphrase, credential file copied over.
    fn sibling(&self, base: &std::path::Path, name: &str, origin: &str) -> Self {
        let m = Self::new(base, name, origin);
        std::fs::copy(
            format!("{}/credentials.enc", self.home),
            format!("{}/credentials.enc", m.home),
        )
        .unwrap();
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
    let tmp = tempdir::TempDir::new("latch-feat-put").unwrap();
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

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The workstation publishes project `app` in prod with three files.
fn seed(tmp: &tempdir::TempDir, origin: &str) -> (Machine, String) {
    let a = Machine::new(tmp.path(), "workstation", origin);
    let pa = a.platform();
    let app = tmp.path().join("work/app");
    write(&app.join(".env"), "TOP=1\n");
    write(&app.join("supersync/.env"), "SYNC=old\n");
    write(&app.join("other/.env"), "OTHER=keep\n");
    let dir = app.display().to_string();
    init::run(&pa, &dir, None).unwrap();
    sync::commit(&pa, &dir, "prod").unwrap();
    sync::push(&pa, &dir, "prod", false, true).unwrap();
    (a, dir)
}

fn remote_files(tmp: &tempdir::TempDir, origin: &str, name: &str) -> Vec<String> {
    let probe = tmp.path().join(name);
    std::process::Command::new("git")
        .args(["clone", "-q", origin])
        .arg(&probe)
        .status()
        .unwrap();
    let mut out: Vec<String> = std::fs::read_dir(probe.join("app/prod"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[test]
fn put_replaces_one_file_and_leaves_the_others_on_the_remote() {
    let (tmp, origin) = scratch();
    let (a, dir) = seed(&tmp, &origin);
    // The dashboard: same credentials, no project directory, never pulled.
    let dash = a.sibling(tmp.path(), "dashboard", &origin);
    let pd = dash.platform();

    let out = put::run(
        &pd,
        &put::Target::Project("app".into()),
        "prod",
        "supersync/.env",
        b"SYNC=new\n",
        None,
        true,
    )
    .unwrap();
    assert!(out.pushed, "a changed file is published");

    assert_eq!(
        remote_files(&tmp, &origin, "probe"),
        vec![".env.enc", "other__.env.enc", "supersync__.env.enc"]
    );
    // The workstation reads the new value, and the untouched ones.
    let pa = a.platform();
    let got = consume::cat(&pa, &dir, "prod", "supersync/.env", false, false).unwrap();
    assert_eq!(got.content, b"SYNC=new\n");
    let other = consume::cat(&pa, &dir, "prod", "other/.env", false, false).unwrap();
    assert_eq!(other.content, b"OTHER=keep\n");
}

#[test]
fn put_refuses_when_the_file_changed_since_it_was_read() {
    let (tmp, origin) = scratch();
    let (a, dir) = seed(&tmp, &origin);
    let dash = a.sibling(tmp.path(), "dashboard", &origin);
    let pd = dash.platform();
    let target = put::Target::Project("app".into());

    // The dashboard reads the file and remembers what it saw…
    let seen = consume::cat_project(&pd, "app", "prod", "supersync/.env").unwrap();
    let expect = sha(&seen);
    // …meanwhile the workstation changes it and pushes.
    let pa = a.platform();
    write(
        &std::path::Path::new(&dir).join("supersync/.env"),
        "SYNC=workstation\n",
    );
    sync::commit(&pa, &dir, "prod").unwrap();
    sync::push(&pa, &dir, "prod", false, true).unwrap();

    let err = put::run(
        &pd,
        &target,
        "prod",
        "supersync/.env",
        b"SYNC=dashboard\n",
        Some(&expect),
        true,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("changed since"), "{err}");
    // Nothing of the dashboard's reached the remote.
    let got = consume::cat(&pa, &dir, "prod", "supersync/.env", false, false).unwrap();
    assert_eq!(got.content, b"SYNC=workstation\n");

    // With the current digest it goes through.
    let now = sha(b"SYNC=workstation\n");
    put::run(
        &pd,
        &target,
        "prod",
        "supersync/.env",
        b"SYNC=dashboard\n",
        Some(&now),
        true,
    )
    .unwrap();
}

#[test]
fn an_unchanged_file_publishes_nothing() {
    let (tmp, origin) = scratch();
    let (a, _dir) = seed(&tmp, &origin);
    let dash = a.sibling(tmp.path(), "dashboard", &origin);
    let out = put::run(
        &dash.platform(),
        &put::Target::Project("app".into()),
        "prod",
        "supersync/.env",
        b"SYNC=old\n",
        None,
        true,
    )
    .unwrap();
    assert!(!out.pushed);
}

#[test]
fn a_project_without_a_key_here_is_refused_not_minted() {
    let (tmp, origin) = scratch();
    let (_a, _dir) = seed(&tmp, &origin);
    // A machine with the repo but none of the project's keys: minting a
    // key here would seal a file nobody else can open.
    let stranger = Machine::new(tmp.path(), "stranger", &origin);
    let err = put::run(
        &stranger.platform(),
        &put::Target::Project("app".into()),
        "prod",
        "supersync/.env",
        b"SYNC=x\n",
        None,
        true,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("no key"), "{err}");
}

#[test]
fn a_clone_with_unpushed_work_is_refused() {
    // put publishes exactly one file; a clone that already holds other
    // staged changes would sweep them into the same push.
    let (tmp, origin) = scratch();
    let (a, dir) = seed(&tmp, &origin);
    let pa = a.platform();
    write(
        &std::path::Path::new(&dir).join("other/.env"),
        "OTHER=staged\n",
    );
    sync::commit(&pa, &dir, "prod").unwrap(); // staged, not pushed
    let err = put::run(
        &pa,
        &put::Target::Project("app".into()),
        "prod",
        "supersync/.env",
        b"SYNC=new\n",
        None,
        true,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("unpushed"), "{err}");
}

#[test]
fn a_group_member_is_refused() {
    let (tmp, origin) = scratch();
    let (a, _dir) = seed(&tmp, &origin);
    let dash = a.sibling(tmp.path(), "dashboard", &origin);
    let err = put::run(
        &dash.platform(),
        &put::Target::Project("app".into()),
        "prod",
        "supersync/.env",
        b"# latch:group=smtp\nX=1\n",
        None,
        true,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("group"), "{err}");
}
