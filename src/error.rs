use thiserror::Error;

#[derive(Error, Debug)]
pub enum LatchError {
    #[error("GitHub API error: {0}")]
    GitHubApi(#[from] octocrab::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key not found. Please run 'latch key set' or set LATCH_KEY env var.")]
    KeyNotFound,

    #[error("Manifest not found in secrets repo. Run 'latch init' first.")]
    ManifestNotFound,

    #[error("Invalid manifest format: {0}")]
    InvalidManifest(String),

    #[error("Project '{0}' not configured. Run 'latch init' or set LATCH_PROJECT env var.")]
    ProjectNotFound(String),

    #[error("Environment '{0}' not found for project '{1}'.")]
    EnvNotFound(String, String),

    #[error("Command error: {0}")]
    Command(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, LatchError>;
