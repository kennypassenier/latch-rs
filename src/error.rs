use thiserror::Error;

/// Typed error variants for the latch library surface.
/// Not all variants are exercised by the current CLI commands but are part of
/// the public library API.
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum LatchError {
    #[error("GitHub API error: {0}")]
    GitHub(String),

    #[error("Encryption/decryption failed: {0}")]
    Crypto(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No encryption key found. Run 'latch init' or set the LATCH_KEY environment variable.")]
    KeyNotFound,

    #[error("No GitHub PAT found. Run 'latch init' or set the LATCH_PAT environment variable.")]
    PatNotFound,

    #[error("manifest.json not found in remote repo. Run 'latch init' first.")]
    ManifestNotFound,

    #[error("Not initialised. Run 'latch init' in your project directory first.")]
    NotInitialised,
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, LatchError>;
