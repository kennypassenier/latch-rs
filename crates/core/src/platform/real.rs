//! Production adapters — the only code in the workspace that touches the
//! real world. Shared by CLI and TUI so each effect has exactly one
//! implementation.

use std::io::Write as _;

use crate::error::LatchError;

use super::{Env, Files, Keyring, ProcOutput, Prompt};

const KEYRING_SERVICE: &str = "latch";

pub struct RealEnv;
impl Env for RealEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

pub struct RealFiles;
impl Files for RealFiles {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, LatchError> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LatchError::other(
                format!("read {}: {}", path, e),
                "check permissions and that the path is reachable",
            )),
        }
    }

    fn write_atomic(&self, path: &str, content: &[u8]) -> Result<(), LatchError> {
        use std::os::unix::fs::OpenOptionsExt;
        let p = std::path::Path::new(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                LatchError::other(
                    format!("create {}: {}", parent.display(), e),
                    "check permissions on the parent directory",
                )
            })?;
        }
        let tmp = format!("{}.tmp", path);
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| {
                    LatchError::other(format!("write {}: {}", tmp, e), "check permissions")
                })?;
            f.write_all(content).map_err(|e| {
                LatchError::other(format!("write {}: {}", tmp, e), "check disk space")
            })?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, path).map_err(|e| {
            LatchError::other(format!("rename to {}: {}", path, e), "check permissions")
        })
    }

    fn remove(&self, path: &str) -> Result<(), LatchError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LatchError::other(
                format!("remove {}: {}", path, e),
                "check permissions",
            )),
        }
    }

    fn try_create_exclusive(&self, path: &str, content: &[u8]) -> Result<bool, LatchError> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut f) => {
                f.write_all(content).ok();
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(LatchError::other(
                format!("lock {}: {}", path, e),
                "check permissions",
            )),
        }
    }

    fn walk(&self, root: &str) -> Result<Vec<String>, LatchError> {
        if !std::path::Path::new(root).is_dir() {
            return Ok(Vec::new());
        }
        Ok(Self::walk_impl(root))
    }

    fn remove_tree(&self, path: &str) -> Result<(), LatchError> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LatchError::other(
                format!("remove {}: {}", path, e),
                "check permissions",
            )),
        }
    }

    fn mtime_unix(&self, path: &str) -> Result<Option<u64>, LatchError> {
        match std::fs::metadata(path) {
            Ok(m) => Ok(m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LatchError::other(
                format!("stat {}: {}", path, e),
                "check permissions",
            )),
        }
    }
}

impl RealFiles {
    fn walk_impl(root: &str) -> Vec<String> {
        let mut out = Vec::new();
        for entry in ignore::WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .build()
            .flatten()
        {
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                if let Ok(rel) = entry.path().strip_prefix(root) {
                    out.push(rel.display().to_string());
                }
            }
        }
        out.sort();
        out
    }
}

pub struct RealKeyring;
impl RealKeyring {
    fn entry(slot: &str) -> Result<keyring::Entry, LatchError> {
        keyring::Entry::new(KEYRING_SERVICE, slot).map_err(|e| {
            LatchError::other(
                format!("keyring entry {}: {}", slot, e),
                "the OS keyring refused the entry — this is unusual; the file backend still works",
            )
        })
    }
}
impl Keyring for RealKeyring {
    fn available(&self) -> bool {
        // A cheap real probe: try to read a well-known slot; transport
        // errors (no Secret Service on this machine) mean unavailable.
        Self::entry("probe")
            .map(|e| matches!(e.get_password(), Ok(_) | Err(keyring::Error::NoEntry)))
            .unwrap_or(false)
    }

    fn get(&self, slot: &str) -> Result<Option<Vec<u8>>, LatchError> {
        match Self::entry(slot)?.get_secret() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(LatchError::other(
                format!("keyring read {}: {}", slot, e),
                "unlock your session keyring, or rely on the file backend (LATCH_PASSPHRASE)",
            )),
        }
    }

    fn set(&self, slot: &str, value: &[u8]) -> Result<(), LatchError> {
        Self::entry(slot)?.set_secret(value).map_err(|e| {
            LatchError::other(
                format!("keyring write {}: {}", slot, e),
                "unlock your session keyring, or rely on the file backend",
            )
        })
    }

    fn delete(&self, slot: &str) -> Result<(), LatchError> {
        match Self::entry(slot)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(LatchError::other(
                format!("keyring delete {}: {}", slot, e),
                "unlock your session keyring",
            )),
        }
    }
}

/// Interactive prompts on a real terminal; hard errors without one (M7).
pub struct RealPrompt {
    interactive: bool,
}

impl RealPrompt {
    pub fn detect(force_non_interactive: bool) -> Self {
        use std::io::IsTerminal;
        Self {
            interactive: !force_non_interactive
                && std::io::stdin().is_terminal()
                && std::io::stderr().is_terminal(),
        }
    }

    fn require(&self, what: &str) -> Result<(), LatchError> {
        if self.interactive {
            Ok(())
        } else {
            Err(LatchError::other(
                format!("'{}' needs interactive input but there is no terminal", what),
                "supply it non-interactively (flags or LATCH_* environment variables) — latch never blocks waiting for hidden input (M7)",
            ))
        }
    }
}

impl Prompt for RealPrompt {
    fn interactive(&self) -> bool {
        self.interactive
    }

    fn passphrase(&self, message: &str) -> Result<String, LatchError> {
        self.require(message)?;
        rpassword::prompt_password(format!("{}: ", message)).map_err(|e| {
            LatchError::other(
                format!("read passphrase: {}", e),
                "retry in a real terminal",
            )
        })
    }

    fn line(&self, message: &str) -> Result<String, LatchError> {
        self.require(message)?;
        eprint!("{}: ", message);
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).map_err(|e| {
            LatchError::other(format!("read input: {}", e), "retry in a real terminal")
        })?;
        Ok(buf.trim().to_string())
    }

    fn confirm(&self, message: &str) -> Result<bool, LatchError> {
        let answer = self.line(&format!("{} [y/N]", message))?;
        Ok(matches!(answer.as_str(), "y" | "Y" | "yes"))
    }
}

pub struct RealClock;
impl super::Clock for RealClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub struct RealProc;
impl super::Proc for RealProc {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
        stdin: Option<&[u8]>,
    ) -> Result<ProcOutput, LatchError> {
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| {
            LatchError::other(
                format!("spawn {}: {}", program, e),
                format!("is '{}' installed and on PATH?", program),
            )
        })?;
        if let Some(input) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                pipe.write_all(input).ok();
            }
        }
        let out = child
            .wait_with_output()
            .map_err(|e| LatchError::other(format!("wait for {}: {}", program, e), "retry"))?;
        Ok(ProcOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn exec_interactive(
        &self,
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> Result<i32, LatchError> {
        use std::process::Command;
        let mut cmd = Command::new(program);
        cmd.args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let status = cmd.status().map_err(|e| {
            LatchError::other(
                format!("spawn {}: {}", program, e),
                format!("is '{}' installed and on PATH?", program),
            )
        })?;
        Ok(status.code().unwrap_or(-1))
    }
}

/// Resolve `~/.latch` (AR15): LATCH_HOME wins; XDG layout via config flag
/// comes later with the config module.
pub fn latch_home(env: &dyn Env) -> String {
    if let Some(h) = env.var("LATCH_HOME") {
        return h;
    }
    let home = dirs::home_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".into());
    format!("{}/.latch", home)
}

/// tmpfs runtime dir for the AR11 session cache.
pub fn runtime_dir(env: &dyn Env) -> Option<String> {
    env.var("XDG_RUNTIME_DIR").map(|d| format!("{}/latch", d))
}
