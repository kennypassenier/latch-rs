//! The Elm-style model (G1): all screen state is plain data, `update`
//! is pure and emits [`Cmd`]s, and only `exec` touches latch-core. Tests
//! build fixture models and snapshot the view — no terminal needed.

use std::collections::BTreeMap;

/// Which key serves a (project, env) cell in the G3 matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCell {
    pub label: String,
    pub generation: u16,
    /// 'E' env var, 'F' credential file, 'K' keyring.
    pub source: char,
    /// True when an env-scoped key (K2) serves this cell.
    pub scoped: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectInfo {
    pub name: String,
    pub dir: String,
    /// Aggregate sync state for the ACTIVE env: clean/modified/local-only/…
    pub state: String,
    /// Per-file states for the active env.
    pub files: Vec<(String, String)>,
    /// env -> which key would serve it (None = missing on this machine).
    pub keys: BTreeMap<String, Option<KeyCell>>,
}

/// Everything `refresh` gathers from core — the fixture unit for tests.
#[derive(Debug, Clone, Default)]
pub struct World {
    pub repo: Option<String>,
    pub projects: Vec<ProjectInfo>,
    /// Union of environments seen in the repo (always contains active).
    pub envs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRow {
    pub file: String,
    pub key: String,
    pub value: String,
    pub revealed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub reference: String,
    pub time_unix: u64,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct Doctor {
    pub latch_home: String,
    pub repo: Option<String>,
    pub pat_source: Option<String>,
    pub keyring_available: bool,
    pub cred_file: bool,
    pub clone_exists: bool,
    /// (file, "ok"|"CORRUPT"|"no key …"|"bad format …")
    pub verify: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Matrix,
    Secrets,
    History,
    Doctor,
    Clone,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Matrix,
        Tab::Secrets,
        Tab::History,
        Tab::Doctor,
        Tab::Clone,
    ];
    pub fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "DASHBOARD",
            Tab::Matrix => "KEY MATRIX",
            Tab::Secrets => "SECRETS",
            Tab::History => "HISTORY",
            Tab::Doctor => "DOCTOR",
            Tab::Clone => "CLONE",
        }
    }
}

/// What an input modal is collecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputPurpose {
    LoginPat,
    LoginRepo { pat: String },
    AddKey,
    AddValue { key: String },
    EditValue { row: usize },
    BackupPath,
    RestorePath,
    CloneTarget,
}

/// What a confirm modal will do on yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAction {
    Rollback { reference: String },
    Rotate { env: Option<String> },
    DeleteRow { row: usize },
}

/// Which operation hit an S4 conflict (G5: interactive choice, never a
/// silent overwrite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictOp {
    Push,
    Pull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    Help,
    Input {
        purpose: InputPurpose,
        title: String,
        buffer: String,
        mask: bool,
    },
    Confirm {
        action: ConfirmAction,
        title: String,
        body: Vec<String>,
    },
    Conflict {
        op: ConflictOp,
        detail: String,
    },
    /// Masked diff lines (G4/G5); reveal re-runs the diff with values.
    Diff {
        lines: Vec<String>,
        revealed: bool,
    },
}

/// Clone-wizard progress (G7), lives on its own tab.
#[derive(Debug, Clone, Default)]
pub struct CloneWizard {
    pub target: String,
    /// None = whole setup, Some(i) = project index; env narrows further.
    pub scope_project: Option<usize>,
    pub scope_env: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub tab: Tab,
    pub world: World,
    pub env: String,
    pub sel_project: usize,
    pub secrets: Vec<SecretRow>,
    pub secrets_sel: usize,
    pub secrets_dirty: bool,
    pub history: Vec<HistoryRow>,
    pub history_sel: usize,
    pub doctor: Doctor,
    pub wizard: CloneWizard,
    pub modal: Option<Modal>,
    /// One-line status of the last operation (the ticker).
    pub status: String,
    pub quit: bool,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            tab: Tab::Dashboard,
            world: World::default(),
            env: "dev".into(),
            sel_project: 0,
            secrets: Vec::new(),
            secrets_sel: 0,
            secrets_dirty: false,
            history: Vec::new(),
            history_sel: 0,
            doctor: Doctor::default(),
            wizard: CloneWizard::default(),
            modal: None,
            status: String::new(),
            quit: false,
        }
    }
}

impl Model {
    pub fn selected_project(&self) -> Option<&ProjectInfo> {
        self.world.projects.get(self.sel_project)
    }
}

/// Every message the app reacts to. Key presses are pre-lowered to
/// semantic keys so update() stays terminal-agnostic (and AZERTY-safe:
/// letters and arrows only, never the number row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Key(Key),
    Op(OpResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
}

/// Results coming back from `exec` — the ONLY producer besides key input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpResult {
    World(WorldSnapshot),
    Secrets(Vec<SecretRow>),
    History(Vec<HistoryRow>),
    DoctorReady(DoctorSnapshot),
    DiffReady { lines: Vec<String>, revealed: bool },
    Done(String),
    Conflict { op: ConflictOp, detail: String },
    Failed(String),
}

// World/Doctor travel through OpResult as concrete snapshots; wrapped in
// dedicated types so OpResult can derive PartialEq for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldSnapshot(pub WorldData);
pub type WorldData = (Option<String>, Vec<ProjectInfo>, Vec<String>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSnapshot(pub Doctor);

impl PartialEq for ProjectInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for ProjectInfo {}
impl PartialEq for Doctor {
    fn eq(&self, other: &Self) -> bool {
        self.latch_home == other.latch_home
    }
}
impl Eq for Doctor {}

/// Commands: what update() wants done. `exec` translates each into the
/// SAME core calls the CLI uses — no parallel logic (G1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    RefreshWorld,
    LoadSecrets,
    LoadHistory,
    LoadDoctor,
    Commit,
    Push {
        force: bool,
    },
    Pull {
        overwrite: bool,
    },
    Diff {
        reveal: bool,
    },
    SaveSecrets {
        rows: Vec<SecretRow>,
    },
    Rollback {
        reference: String,
    },
    Rotate {
        env: Option<String>,
    },
    Backup {
        path: String,
    },
    Restore {
        path: String,
    },
    Login {
        pat: String,
        repo: String,
    },
    CloneTo {
        target: String,
        project: Option<String>,
        env: Option<String>,
    },
}
