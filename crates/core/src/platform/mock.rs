//! Scripted test doubles (AR1/AR7): in-memory everything, recorded calls,
//! controllable time and interactivity. Every destructive-path test in the
//! workspace runs against these.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::error::LatchError;

use super::{Clock, Env, Files, Keyring, Proc, ProcOutput, Prompt};

#[derive(Default)]
pub struct MockEnv {
    pub vars: RefCell<HashMap<String, String>>,
}
impl MockEnv {
    pub fn set(&self, k: &str, v: &str) {
        self.vars.borrow_mut().insert(k.into(), v.into());
    }
}
impl Env for MockEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.vars.borrow().get(name).cloned()
    }
}

#[derive(Default)]
pub struct MockFiles {
    pub files: RefCell<HashMap<String, Vec<u8>>>,
    pub mtimes: RefCell<HashMap<String, u64>>,
}
impl MockFiles {
    pub fn seed(&self, path: &str, content: &[u8]) {
        self.files
            .borrow_mut()
            .insert(path.into(), content.to_vec());
    }
    pub fn set_mtime(&self, path: &str, t: u64) {
        self.mtimes.borrow_mut().insert(path.into(), t);
    }
}
impl Files for MockFiles {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, LatchError> {
        Ok(self.files.borrow().get(path).cloned())
    }
    fn write_atomic(&self, path: &str, content: &[u8]) -> Result<(), LatchError> {
        self.files
            .borrow_mut()
            .insert(path.into(), content.to_vec());
        Ok(())
    }
    fn remove(&self, path: &str) -> Result<(), LatchError> {
        self.files.borrow_mut().remove(path);
        Ok(())
    }
    fn try_create_exclusive(&self, path: &str, content: &[u8]) -> Result<bool, LatchError> {
        let mut files = self.files.borrow_mut();
        if files.contains_key(path) {
            return Ok(false);
        }
        files.insert(path.into(), content.to_vec());
        Ok(true)
    }
    fn mtime_unix(&self, path: &str) -> Result<Option<u64>, LatchError> {
        if !self.files.borrow().contains_key(path) {
            return Ok(None);
        }
        Ok(Some(*self.mtimes.borrow().get(path).unwrap_or(&0)))
    }
}

pub struct MockKeyring {
    pub available: bool,
    pub slots: RefCell<HashMap<String, Vec<u8>>>,
}
impl Default for MockKeyring {
    fn default() -> Self {
        Self {
            available: true,
            slots: RefCell::new(HashMap::new()),
        }
    }
}
impl MockKeyring {
    pub fn headless() -> Self {
        Self {
            available: false,
            slots: RefCell::new(HashMap::new()),
        }
    }
}
impl Keyring for MockKeyring {
    fn available(&self) -> bool {
        self.available
    }
    fn get(&self, slot: &str) -> Result<Option<Vec<u8>>, LatchError> {
        if !self.available {
            return Ok(None);
        }
        Ok(self.slots.borrow().get(slot).cloned())
    }
    fn set(&self, slot: &str, value: &[u8]) -> Result<(), LatchError> {
        if !self.available {
            return Err(LatchError::other(
                "keyring unavailable",
                "file backend should have been chosen — caller bug",
            ));
        }
        self.slots.borrow_mut().insert(slot.into(), value.to_vec());
        Ok(())
    }
    fn delete(&self, slot: &str) -> Result<(), LatchError> {
        self.slots.borrow_mut().remove(slot);
        Ok(())
    }
}

/// Scripted prompt: pops answers front-to-back; records what was asked.
pub struct MockPrompt {
    pub interactive: bool,
    pub passphrases: RefCell<Vec<String>>,
    pub lines: RefCell<Vec<String>>,
    pub confirms: RefCell<Vec<bool>>,
    pub asked: RefCell<Vec<String>>,
}
impl Default for MockPrompt {
    fn default() -> Self {
        Self {
            interactive: true,
            passphrases: RefCell::new(Vec::new()),
            lines: RefCell::new(Vec::new()),
            confirms: RefCell::new(Vec::new()),
            asked: RefCell::new(Vec::new()),
        }
    }
}
impl MockPrompt {
    pub fn non_interactive() -> Self {
        Self {
            interactive: false,
            ..Default::default()
        }
    }
    fn gate(&self, what: &str) -> Result<(), LatchError> {
        self.asked.borrow_mut().push(what.to_string());
        if self.interactive {
            Ok(())
        } else {
            Err(LatchError::other(
                format!("'{}' needs interactive input but there is no terminal", what),
                "supply it non-interactively (flags or LATCH_* environment variables) — latch never blocks (M7)",
            ))
        }
    }
}
impl Prompt for MockPrompt {
    fn interactive(&self) -> bool {
        self.interactive
    }
    fn passphrase(&self, message: &str) -> Result<String, LatchError> {
        self.gate(message)?;
        self.passphrases
            .borrow_mut()
            .pop()
            .ok_or_else(|| LatchError::other("mock: no passphrase scripted", "test bug"))
    }
    fn line(&self, message: &str) -> Result<String, LatchError> {
        self.gate(message)?;
        self.lines
            .borrow_mut()
            .pop()
            .ok_or_else(|| LatchError::other("mock: no line scripted", "test bug"))
    }
    fn confirm(&self, message: &str) -> Result<bool, LatchError> {
        self.gate(message)?;
        Ok(self.confirms.borrow_mut().pop().unwrap_or(false))
    }
}

pub struct MockClock {
    pub now: RefCell<u64>,
}
impl Default for MockClock {
    fn default() -> Self {
        Self {
            now: RefCell::new(1_800_000_000),
        }
    }
}
impl MockClock {
    pub fn advance(&self, secs: u64) {
        *self.now.borrow_mut() += secs;
    }
}
impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        *self.now.borrow()
    }
}

/// A scripted response: (matcher, exit status, stdout, stderr).
pub type ProcResponse = (String, i32, Vec<u8>, Vec<u8>);

/// Scripted subprocess runner: matches on substring of `program args...`,
/// first match wins; unmatched commands succeed with empty output.
#[derive(Default)]
pub struct MockProc {
    pub responses: RefCell<Vec<ProcResponse>>,
    pub calls: RefCell<Vec<String>>,
    pub env_log: RefCell<Vec<Vec<(String, String)>>>,
}
impl MockProc {
    pub fn respond(&self, matcher: &str, status: i32, stdout: &[u8], stderr: &[u8]) {
        self.responses.borrow_mut().push((
            matcher.into(),
            status,
            stdout.to_vec(),
            stderr.to_vec(),
        ));
    }
    pub fn calls_containing(&self, needle: &str) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.contains(needle))
            .cloned()
            .collect()
    }
}
impl Proc for MockProc {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
        _stdin: Option<&[u8]>,
    ) -> Result<ProcOutput, LatchError> {
        let rendered = format!("{} {}", program, args.join(" "));
        self.calls.borrow_mut().push(rendered.clone());
        self.env_log.borrow_mut().push(
            envs.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        for (matcher, status, stdout, stderr) in self.responses.borrow().iter() {
            if rendered.contains(matcher.as_str()) {
                return Ok(ProcOutput {
                    status: *status,
                    stdout: stdout.clone(),
                    stderr: stderr.clone(),
                });
            }
        }
        Ok(ProcOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}
