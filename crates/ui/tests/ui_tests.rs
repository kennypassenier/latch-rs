//! G1 snapshot + behaviour tests: fixture models rendered on a
//! TestBackend (no terminal), and update() driven by key messages with
//! the emitted commands asserted — the UI's whole contract.

use latch_ui::model::*;
use latch_ui::update::update;
use latch_ui::view::render;

fn render_text(m: &Model) -> String {
    let backend = ratatui::backend::TestBackend::new(110, 32);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| render(m, f)).unwrap();
    let buf = term.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn key(m: &mut Model, k: Key) -> Vec<Cmd> {
    update(m, Msg::Key(k))
}

fn fixture_world() -> World {
    let mut alpha = ProjectInfo {
        name: "alpha".into(),
        dir: "/w/alpha".into(),
        state: "clean".into(),
        files: vec![(".env".into(), "clean".into())],
        ..Default::default()
    };
    alpha.keys.insert(
        "dev".into(),
        Some(KeyCell {
            label: "alpha".into(),
            generation: 1,
            source: 'F',
            scoped: false,
        }),
    );
    alpha.keys.insert(
        "prod".into(),
        Some(KeyCell {
            label: "alpha.prod".into(),
            generation: 3,
            source: 'E',
            scoped: true,
        }),
    );
    let mut beta = ProjectInfo {
        name: "beta".into(),
        dir: "/w/beta".into(),
        state: "modified".into(),
        files: vec![(".env".into(), "modified".into())],
        ..Default::default()
    };
    beta.keys.insert("dev".into(), None);
    beta.keys.insert("prod".into(), None);
    World {
        repo: Some("kenny/secrets".into()),
        projects: vec![alpha, beta],
        envs: vec!["dev".into(), "prod".into()],
    }
}

fn fixture_model() -> Model {
    Model {
        world: fixture_world(),
        ..Default::default()
    }
}

// ── G2 · dashboard ──────────────────────────────────────────────────────

#[test]
fn dashboard_shows_states_and_missing_keys() {
    let m = fixture_model();
    let text = render_text(&m);
    assert!(text.contains("alpha"));
    assert!(text.contains("clean"));
    assert!(text.contains("beta"));
    assert!(text.contains("modified"));
    assert!(text.contains("alpha#1 [F]"), "key cell for the active env");
    assert!(text.contains("MISSING"), "beta has no dev key");
    assert!(text.contains("kenny/secrets"));
}

// ── G3 · matrix ─────────────────────────────────────────────────────────

#[test]
fn matrix_renders_per_cell_source_markers() {
    let mut m = fixture_model();
    m.tab = Tab::Matrix;
    let text = render_text(&m);
    assert!(text.contains("F#1"), "file-sourced project key: {text}");
    assert!(text.contains("E*#3"), "env-sourced SCOPED key: {text}");
    assert!(text.contains("✗"), "missing cells are marked");
    assert!(text.contains("dev") && text.contains("prod"));
}

// ── G4 · secrets stay masked in the buffer ──────────────────────────────

#[test]
fn secret_values_never_render_unless_revealed() {
    let mut m = fixture_model();
    m.tab = Tab::Secrets;
    m.secrets = vec![SecretRow {
        file: ".env".into(),
        key: "DB_PASSWORD".into(),
        value: "hunter2-super-secret".into(),
        revealed: false,
    }];
    let text = render_text(&m);
    assert!(text.contains("DB_PASSWORD"));
    assert!(
        !text.contains("hunter2-super-secret"),
        "masked value leaked into the render buffer"
    );
    assert!(text.contains("••••"));

    // Explicit per-row reveal (G4).
    key(&mut m, Key::Char('r'));
    let text = render_text(&m);
    assert!(text.contains("hunter2-super-secret"));
}

#[test]
fn secrets_edit_flow_marks_dirty_and_saves_via_core_cmd() {
    let mut m = fixture_model();
    m.tab = Tab::Secrets;
    m.secrets = vec![SecretRow {
        file: ".env".into(),
        key: "TOKEN".into(),
        value: "old".into(),
        revealed: false,
    }];

    // modify → input modal → type → enter
    key(&mut m, Key::Char('m'));
    assert!(matches!(m.modal, Some(Modal::Input { .. })));
    for c in "newvalue".chars() {
        key(&mut m, Key::Char(c));
    }
    let cmds = key(&mut m, Key::Enter);
    assert!(cmds.is_empty());
    assert_eq!(m.secrets[0].value, "newvalue");
    assert!(m.secrets_dirty);
    let text = render_text(&m);
    assert!(text.contains("[UNSAVED]"));

    // save emits the core-backed command with the rows
    let cmds = key(&mut m, Key::Char('s'));
    assert!(matches!(&cmds[..], [Cmd::SaveSecrets { rows }] if rows[0].value == "newvalue"));

    // delete goes through a confirm
    key(&mut m, Key::Char('x'));
    assert!(matches!(m.modal, Some(Modal::Confirm { .. })));
    key(&mut m, Key::Char('y'));
    assert!(m.secrets.is_empty());
}

// ── G5 · conflicts are an interactive choice, never silent ──────────────

#[test]
fn s4_conflict_renders_choice_dialog_and_only_o_forces() {
    let mut m = fixture_model();

    // Push from the dashboard is NEVER force by default.
    let cmds = key(&mut m, Key::Char('p'));
    assert_eq!(cmds, vec![Cmd::Push { force: false }]);

    // The op comes back as a conflict → dialog appears.
    update(
        &mut m,
        Msg::Op(OpResult::Conflict {
            op: ConflictOp::Push,
            detail: "the remote has newer changes than your base (S4)".into(),
        }),
    );
    let text = render_text(&m);
    assert!(text.contains("S4"));
    assert!(text.contains("[p] pull"));
    assert!(text.contains("[o] overwrite deliberately"));

    // Escape = do nothing.
    key(&mut m, Key::Esc);
    assert!(m.modal.is_none());

    // Re-open and choose overwrite → force push, exactly once.
    update(
        &mut m,
        Msg::Op(OpResult::Conflict {
            op: ConflictOp::Push,
            detail: "S4".into(),
        }),
    );
    let cmds = key(&mut m, Key::Char('o'));
    assert_eq!(cmds, vec![Cmd::Push { force: true }]);

    // Same for pull: overwrite key maps to pull --overwrite.
    update(
        &mut m,
        Msg::Op(OpResult::Conflict {
            op: ConflictOp::Pull,
            detail: "S4".into(),
        }),
    );
    let cmds = key(&mut m, Key::Char('o'));
    assert_eq!(cmds, vec![Cmd::Pull { overwrite: true }]);
}

// ── G6 · history + rollback emits the right core call ───────────────────

#[test]
fn rollback_needs_confirmation_and_emits_core_call() {
    let mut m = fixture_model();
    m.tab = Tab::History;
    m.history = vec![
        HistoryRow {
            reference: "abc123".into(),
            time_unix: 1_700_000_000,
            message: "push alpha/dev".into(),
        },
        HistoryRow {
            reference: "def456".into(),
            time_unix: 1_600_000_000,
            message: "older".into(),
        },
    ];
    let text = render_text(&m);
    assert!(text.contains("abc123") && text.contains("push alpha/dev"));

    // Select the second entry, ask for rollback.
    key(&mut m, Key::Down);
    key(&mut m, Key::Char('R'));
    let Some(Modal::Confirm { .. }) = &m.modal else {
        panic!("rollback must confirm first");
    };
    let text = render_text(&m);
    assert!(text.contains("def456"));

    // Any non-yes key cancels…
    let cmds = key(&mut m, Key::Char('n'));
    assert!(cmds.is_empty() && m.modal.is_none());

    // …and yes emits EXACTLY the core rollback call.
    key(&mut m, Key::Char('R'));
    let cmds = key(&mut m, Key::Char('y'));
    assert_eq!(
        cmds,
        vec![Cmd::Rollback {
            reference: "def456".into()
        }]
    );
}

// ── G8 · doctor panel ───────────────────────────────────────────────────

#[test]
fn doctor_renders_state_and_verify_verdicts() {
    let mut m = fixture_model();
    m.tab = Tab::Doctor;
    m.doctor = Doctor {
        latch_home: "/home/kenny/.latch".into(),
        repo: Some("kenny/secrets".into()),
        pat_source: Some("Keyring".into()),
        keyring_available: true,
        cred_file: false,
        clone_exists: true,
        verify: vec![
            ("alpha/dev/.env.enc".into(), "ok".into()),
            ("beta/dev/.env.enc".into(), "CORRUPT".into()),
        ],
    };
    let text = render_text(&m);
    assert!(text.contains("/home/kenny/.latch"));
    assert!(text.contains("CORRUPT"), "red verdicts visible");
    assert!(text.contains("ok"));

    // G9: rotation asks first and the caveat is in the dialog.
    key(&mut m, Key::Char('R'));
    let text = render_text(&m);
    assert!(text.contains("OLD key"), "K3 caveat shown: {text}");
    let cmds = key(&mut m, Key::Enter);
    assert_eq!(cmds, vec![Cmd::Rotate { env: None }]);
}

// ── G9 · login flow (masked input) ──────────────────────────────────────

#[test]
fn login_flow_masks_pat_and_emits_login() {
    let mut m = fixture_model();
    m.tab = Tab::Doctor;
    key(&mut m, Key::Char('l'));
    for c in "ghp_secret".chars() {
        key(&mut m, Key::Char(c));
    }
    let text = render_text(&m);
    assert!(
        !text.contains("ghp_secret"),
        "PAT typed into a masked input leaked"
    );
    key(&mut m, Key::Enter); // → repo input (prefilled)
    let Some(Modal::Input { buffer, .. }) = &m.modal else {
        panic!("repo input expected");
    };
    assert_eq!(buffer, "kenny/secrets");
    let cmds = key(&mut m, Key::Enter);
    assert_eq!(
        cmds,
        vec![Cmd::Login {
            pat: "ghp_secret".into(),
            repo: "kenny/secrets".into()
        }]
    );
}

// ── G7 · clone wizard ───────────────────────────────────────────────────

#[test]
fn clone_wizard_scopes_and_runs() {
    let mut m = fixture_model();
    m.tab = Tab::Clone;

    // No target yet: enter refuses.
    let cmds = key(&mut m, Key::Enter);
    assert!(cmds.is_empty());
    assert!(m.status.contains("target"));

    // Set target via [t] input.
    key(&mut m, Key::Char('t'));
    for c in "kenny@vm".chars() {
        key(&mut m, Key::Char(c));
    }
    key(&mut m, Key::Enter);
    assert_eq!(m.wizard.target, "kenny@vm");

    // Whole setup by default.
    let cmds = key(&mut m, Key::Enter);
    assert_eq!(
        cmds,
        vec![Cmd::CloneTo {
            target: "kenny@vm".into(),
            project: None,
            env: None
        }]
    );

    // Scope to project + env.
    key(&mut m, Key::Right); // alpha
    key(&mut m, Key::Char('e')); // dev
    let text = render_text(&m);
    assert!(text.contains("project alpha"));
    let cmds = key(&mut m, Key::Enter);
    assert_eq!(
        cmds,
        vec![Cmd::CloneTo {
            target: "kenny@vm".into(),
            project: Some("alpha".into()),
            env: Some("dev".into())
        }]
    );
}

// ── G1 · tab cycling loads the right data ───────────────────────────────

#[test]
fn tab_cycle_requests_screen_data() {
    let mut m = fixture_model();
    assert_eq!(key(&mut m, Key::Tab), vec![]); // → Matrix (no load)
    assert_eq!(key(&mut m, Key::Tab), vec![Cmd::LoadSecrets]);
    assert_eq!(key(&mut m, Key::Tab), vec![Cmd::LoadHistory]);
    assert_eq!(key(&mut m, Key::Tab), vec![Cmd::LoadDoctor]);
    assert_eq!(m.tab, Tab::Doctor);
    // Env cycling refreshes the world.
    let cmds = key(&mut m, Key::Char('e'));
    assert_eq!(m.env, "prod");
    assert_eq!(cmds, vec![Cmd::RefreshWorld]);
}
