//! Terminal runtime (G1): raw-mode loop over crossterm events. All logic
//! lives in update/exec — this file only translates events and draws.

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::{execute, terminal};

use latch_core::error::LatchError;
use latch_core::platform::real::{
    latch_home, runtime_dir, RealClock, RealEnv, RealFiles, RealKeyring, RealProc, RealPrompt,
};
use latch_core::platform::Platform;

use crate::model::{Cmd, Key, Model, Msg, Tab};
use crate::{exec, update, view};

fn lower(code: KeyCode, mods: KeyModifiers) -> Option<Key> {
    Some(match code {
        KeyCode::Char(c) => {
            if mods.contains(KeyModifiers::CONTROL) && (c == 'c' || c == 'q') {
                return Some(Key::Char('q'));
            }
            Key::Char(c)
        }
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Backspace => Key::Backspace,
        _ => return None,
    })
}

/// Run the TUI on the real platform until quit.
pub fn run() -> Result<(), LatchError> {
    let env = RealEnv;
    let files = RealFiles;
    let keyring = RealKeyring;
    let prompt = RealPrompt::detect(false);
    let clock = RealClock;
    let proc = RealProc;
    let home = latch_home(&env);
    let runtime = runtime_dir(&env);
    let platform = Platform {
        env: &env,
        files: &files,
        keyring: &keyring,
        prompt: &prompt,
        clock: &clock,
        proc: &proc,
        latch_home: home,
        runtime_dir: runtime,
    };
    let cwd = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();

    terminal::enable_raw_mode().map_err(term_err)?;
    let mut stdout = std::io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen).map_err(term_err)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal_ui = ratatui::Terminal::new(backend).map_err(term_err)?;

    let mut model = Model::default();
    run_cmds(
        &mut model,
        vec![Cmd::RefreshWorld, Cmd::LoadDoctor],
        &platform,
        &cwd,
        &mut terminal_ui,
    );

    let result = loop {
        if let Err(e) = terminal_ui.draw(|f| view::render(&model, f)) {
            break Err(term_err(e));
        }
        match event::read() {
            Err(e) => break Err(term_err(e)),
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                if let Some(key) = lower(k.code, k.modifiers) {
                    let cmds = update::update(&mut model, Msg::Key(key));
                    run_cmds(&mut model, cmds, &platform, &cwd, &mut terminal_ui);
                }
            }
            Ok(_) => {}
        }
        if model.quit {
            break Ok(());
        }
    };

    let _ = terminal::disable_raw_mode();
    let _ = execute!(std::io::stdout(), terminal::LeaveAlternateScreen);
    result
}

/// Execute commands synchronously, drawing a busy banner first so slow
/// operations (git over the network, Argon2) are visibly in progress.
fn run_cmds<B: ratatui::backend::Backend>(
    model: &mut Model,
    mut cmds: Vec<Cmd>,
    platform: &Platform,
    cwd: &str,
    terminal_ui: &mut ratatui::Terminal<B>,
) {
    // Commands can cascade (an op result may request a refresh).
    let mut guard = 0;
    while !cmds.is_empty() && guard < 8 {
        guard += 1;
        let mut next = Vec::new();
        for cmd in cmds.drain(..) {
            model.status = format!("working: {:?}…", kind_of(&cmd));
            let _ = terminal_ui.draw(|f| view::render(model, f));
            let msg = exec::exec(cmd, model, platform, cwd);
            next.extend(update::update(model, msg));
        }
        cmds = next;
    }
    if model.status.starts_with("working:") {
        model.status.clear();
    }
    // Keep dependent panes in sync after world changes.
    if model.tab == Tab::Secrets && model.secrets.is_empty() && !model.secrets_dirty {
        let msg = exec::exec(Cmd::LoadSecrets, model, platform, cwd);
        let _ = update::update(model, msg);
    }
}

fn kind_of(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::RefreshWorld => "refresh",
        Cmd::LoadSecrets => "read secrets",
        Cmd::LoadHistory => "history",
        Cmd::LoadDoctor => "doctor",
        Cmd::Commit => "commit",
        Cmd::Push { .. } => "push",
        Cmd::Pull { .. } => "pull",
        Cmd::Diff { .. } => "diff",
        Cmd::SaveSecrets { .. } => "save",
        Cmd::Rollback { .. } => "rollback",
        Cmd::Rotate { .. } => "rotate",
        Cmd::Backup { .. } => "backup",
        Cmd::Restore { .. } => "restore",
        Cmd::Login { .. } => "login",
        Cmd::CloneTo { .. } => "clone",
    }
}

fn term_err(e: std::io::Error) -> LatchError {
    LatchError::other(
        format!("terminal error: {}", e),
        "the TUI needs an interactive terminal; use the latch CLI verbs headless",
    )
}
