//! The exec mapping layer (Cmd → core → OpResult) against a real git
//! origin — the one UI module the fixture snapshots cannot cover:
//! world refresh, S4 conflict detection, masked diff, save round-trip.

use latch_core::config::Config;
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockPrompt};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Platform;
use latch_ui::exec::exec;
use latch_ui::model::*;
use latch_ui::update::update;

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

fn refreshed(m: &mut Model, p: &Platform) {
    let msg = exec(Cmd::RefreshWorld, m, p, "/");
    update(m, msg);
}

#[test]
fn exec_maps_every_command_to_core_faithfully() {
    let tmp = tempdir::TempDir::new("latch-ui-exec").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let origin = format!("file://{}", bare.display());

    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work-a/uiapp");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), "TOKEN=first\n").unwrap();
    latch_core::ops::init::run(&pa, &proj.display().to_string(), None).unwrap();

    let mut m = Model::default();

    // ── RefreshWorld builds the dashboard/matrix data from core ─────────
    refreshed(&mut m, &pa);
    assert_eq!(m.world.repo.as_deref(), Some(origin.as_str()));
    assert_eq!(m.world.projects.len(), 1);
    let info = &m.world.projects[0];
    assert_eq!(info.name, "uiapp");
    assert_eq!(info.state, "modified", "uncommitted file counts as work");

    // ── Commit + Push through exec ──────────────────────────────────────
    let msg = exec(Cmd::Commit, &m, &pa, "/");
    assert!(
        matches!(&msg, Msg::Op(OpResult::Done(s)) if s.contains("committed")),
        "{msg:?}"
    );
    update(&mut m, msg);
    // D13: the TUI pushes through the same gate as the CLI — no silent
    // exemption for the shell you happen to use — so the escrow has to
    // exist here just as it would for a person.
    latch_core::ops::keyops::backup(&pa, &tmp.path().join("escrow.bk").display().to_string())
        .unwrap();
    let msg = exec(Cmd::Push { force: false }, &m, &pa, "/");
    assert!(
        matches!(&msg, Msg::Op(OpResult::Done(s)) if s.contains("pushed")),
        "{msg:?}"
    );
    refreshed(&mut m, &pa);
    assert_eq!(m.world.projects[0].state, "clean");
    let cell = m.world.projects[0]
        .keys
        .get("dev")
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(cell.label, "uiapp");
    assert_eq!(cell.source, 'F', "headless keyring → file backend");

    // ── LoadSecrets + SaveSecrets round-trip ────────────────────────────
    let msg = exec(Cmd::LoadSecrets, &m, &pa, "/");
    update(&mut m, msg);
    assert_eq!(m.secrets.len(), 1);
    assert_eq!(m.secrets[0].key, "TOKEN");
    let mut rows = m.secrets.clone();
    rows[0].value = "edited-via-ui".into();
    let msg = exec(Cmd::SaveSecrets { rows }, &m, &pa, "/");
    assert!(matches!(&msg, Msg::Op(OpResult::Done(_))), "{msg:?}");
    assert!(std::fs::read_to_string(proj.join(".env"))
        .unwrap()
        .contains("TOKEN=edited-via-ui"));
    refreshed(&mut m, &pa);
    assert_eq!(m.world.projects[0].state, "clean", "save committed too");

    // ── Diff stays masked unless asked ──────────────────────────────────
    std::fs::write(proj.join(".env"), "TOKEN=next\n").unwrap();
    let msg = exec(Cmd::Diff { reveal: false }, &m, &pa, "/");
    let Msg::Op(OpResult::DiffReady { lines, revealed }) = msg else {
        panic!("diff expected");
    };
    assert!(!revealed);
    let text = lines.join("\n");
    assert!(text.contains("TOKEN"), "{text}");
    assert!(
        !text.contains("next") && !text.contains("edited-via-ui"),
        "masked: {text}"
    );

    // ── S4 conflict is detected and mapped, not raw-errored ─────────────
    // A second machine pushes past us.
    let b = Machine::new(tmp.path(), "home-b", &origin);
    let store_a = latch_core::credentials::CredStore::new(&pa);
    let (raw_key, _) = store_a.get("key:uiapp").unwrap().unwrap();
    b.env.set("LATCH_KEY_UIAPP", &hex::encode(&raw_key));
    let pb = b.platform();
    let proj_b = tmp.path().join("work-b/uiapp");
    std::fs::create_dir_all(&proj_b).unwrap();
    latch_core::ops::init::run(&pb, &proj_b.display().to_string(), Some("uiapp".into())).unwrap();
    latch_core::ops::sync::pull(&pb, &proj_b.display().to_string(), "dev", false, false).unwrap();
    std::fs::write(proj_b.join(".env"), "TOKEN=from-b\n").unwrap();
    latch_core::ops::sync::commit(&pb, &proj_b.display().to_string(), "dev").unwrap();
    latch_core::ops::sync::push(&pb, &proj_b.display().to_string(), "dev", false, true).unwrap();

    // Our local edit → commit → push must surface as a Conflict op.
    let msg = exec(Cmd::Commit, &m, &pa, "/");
    update(&mut m, msg);
    let msg = exec(Cmd::Push { force: false }, &m, &pa, "/");
    assert!(
        matches!(&msg, Msg::Op(OpResult::Conflict { op: ConflictOp::Push, detail }) if detail.contains("S4")),
        "{msg:?}"
    );
    // The deliberate overwrite path resolves it.
    let msg = exec(Cmd::Push { force: true }, &m, &pa, "/");
    assert!(matches!(&msg, Msg::Op(OpResult::Done(_))), "{msg:?}");

    // ── History + rollback mapping ──────────────────────────────────────
    let msg = exec(Cmd::LoadHistory, &m, &pa, "/");
    update(&mut m, msg);
    assert!(m.history.len() >= 2, "{:?}", m.history);
    let msg = exec(
        Cmd::Rollback {
            reference: "doesnotexist".into(),
        },
        &m,
        &pa,
        "/",
    );
    assert!(
        matches!(&msg, Msg::Op(OpResult::Failed(e)) if e.contains("::")),
        "errors keep their remedy through the mapping: {msg:?}"
    );

    // ── Doctor mapping ──────────────────────────────────────────────────
    let msg = exec(Cmd::LoadDoctor, &m, &pa, "/");
    update(&mut m, msg);
    assert!(m.doctor.clone_exists);
    assert!(m.doctor.cred_file);
    assert!(!m.doctor.verify.is_empty());
    assert!(
        m.doctor.verify.iter().all(|(_, v)| v == "ok"),
        "{:?}",
        m.doctor.verify
    );
}
