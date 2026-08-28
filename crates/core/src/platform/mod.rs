//! The I/O boundary (AR1): every effect the core needs from the outside
//! world is a trait here. Logic never touches std::env/fs/process
//! directly — it receives a [`Platform`]. `real` holds the production
//! adapters (shared by CLI and TUI so there is exactly one
//! implementation); `mock` holds the scripted test doubles.

pub mod mock;
pub mod real;

use crate::error::LatchError;

/// Environment variables (K4 env-override layer, M7 detection).
pub trait Env {
    fn var(&self, name: &str) -> Option<String>;
}

/// File access. Writes are atomic (temp + rename) and 0600 by contract
/// (AR6): a crash can never leave a half-written or world-readable file.
pub trait Files {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, LatchError>;
    fn write_atomic(&self, path: &str, content: &[u8]) -> Result<(), LatchError>;
    /// Atomically write an EXECUTABLE file (0755): temp + chmod + rename,
    /// so a crash never leaves a written-but-not-executable binary (K1,
    /// the M5 self-update placement). Default mirrors write_atomic for
    /// backends where the mode is irrelevant (the mock).
    fn write_executable(&self, path: &str, content: &[u8]) -> Result<(), LatchError> {
        self.write_atomic(path, content)
    }
    fn remove(&self, path: &str) -> Result<(), LatchError>;
    /// Create a file exclusively (fails if it exists) — the AR12 lock
    /// primitive.
    fn try_create_exclusive(&self, path: &str, content: &[u8]) -> Result<bool, LatchError>;
    /// Modification time as unix seconds, None if absent (AR11 TTL).
    fn mtime_unix(&self, path: &str) -> Result<Option<u64>, LatchError>;
    /// Recursively list files under `root` (relative paths, sorted),
    /// honouring `.latchignore` and the built-in directory list (D8) —
    /// never `.gitignore`. Missing root = empty list.
    fn walk(&self, root: &str) -> Result<Vec<String>, LatchError>;
    /// The same walk with NO exclusions at all: the secrets clone, where
    /// every ciphertext counts and an ignore file must never be able to
    /// hide one, and the `--no-ignore` diagnostic (D8).
    fn walk_all(&self, root: &str) -> Result<Vec<String>, LatchError>;
    /// Remove a directory tree (W9 reset). Missing tree is fine.
    fn remove_tree(&self, path: &str) -> Result<(), LatchError>;
}

/// OS keyring (K4 primary layer on desktops). `available` is a cheap
/// probe; on headless machines it returns false and the file backend
/// takes over.
pub trait Keyring {
    fn available(&self) -> bool;
    fn get(&self, slot: &str) -> Result<Option<Vec<u8>>, LatchError>;
    fn set(&self, slot: &str, value: &[u8]) -> Result<(), LatchError>;
    fn delete(&self, slot: &str) -> Result<(), LatchError>;
}

/// Interactive prompting. In non-interactive contexts (M7) every method
/// MUST return an error — hanging on hidden input is the v1 sync-stall
/// bug class and is designed out here.
pub trait Prompt {
    fn interactive(&self) -> bool;
    fn passphrase(&self, message: &str) -> Result<String, LatchError>;
    fn line(&self, message: &str) -> Result<String, LatchError>;
    fn confirm(&self, message: &str) -> Result<bool, LatchError>;
}

/// Wall clock (AR11 TTL); injected so tests control time.
pub trait Clock {
    fn now_unix(&self) -> u64;
}

/// Subprocess execution (AR2 git, M2 ssh). `envs` exist so secrets travel
/// via the environment, never argv (visible in `ps`).
pub struct ProcOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait Proc {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
        stdin: Option<&[u8]>,
    ) -> Result<ProcOutput, LatchError>;
    /// Run a child with INHERITED stdio (W6 latch run): the child owns the
    /// terminal; we only add env vars and report its exit code. Secrets go
    /// through `envs` — process memory, never disk.
    fn exec_interactive(
        &self,
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> Result<i32, LatchError>;
}

/// Everything the core needs, in one bundle.
pub struct Platform<'a> {
    pub env: &'a dyn Env,
    pub files: &'a dyn Files,
    pub keyring: &'a dyn Keyring,
    pub prompt: &'a dyn Prompt,
    pub clock: &'a dyn Clock,
    pub proc: &'a dyn Proc,
    /// `~/.latch` (or LATCH_HOME) — resolved by the shell at startup.
    pub latch_home: String,
    /// tmpfs runtime dir for the AR11 session cache (e.g. /run/user/1000).
    /// None disables session caching entirely.
    pub runtime_dir: Option<String>,
}
