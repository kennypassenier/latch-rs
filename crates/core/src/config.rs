//! Global config (D4/AR15): ~/.latch/config.toml — non-secret metadata
//! only. Projects registry lives here; secrets never do (tested).

use serde::{Deserialize, Serialize};

use crate::error::LatchError;
use crate::platform::Platform;

pub const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Config {
    /// The private secrets repository, e.g. "kennypassenier/secrets".
    #[serde(default)]
    pub repo: Option<String>,
    /// AR11 session TTL in seconds; None = default (900), Some(0) = off.
    #[serde(default)]
    pub session_ttl: Option<u64>,
    #[serde(default)]
    pub projects: Vec<Project>,
    /// M4: where 'latch update' maintains the binary. None = alongside
    /// the currently running executable.
    #[serde(default)]
    pub install_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Project {
    pub name: String,
    /// Linked working directory on THIS machine (absolute).
    pub dir: String,
}

impl Config {
    pub fn path(p: &Platform) -> String {
        format!("{}/{}", p.latch_home, CONFIG_FILE)
    }

    pub fn load(p: &Platform) -> Result<Self, LatchError> {
        let Some(raw) = p.files.read(&Self::path(p))? else {
            return Ok(Self::default());
        };
        let text = String::from_utf8(raw).map_err(|_| LatchError::Format {
            context: CONFIG_FILE.into(),
            detail: "not utf-8".into(),
        })?;
        toml::from_str(&text).map_err(|e| LatchError::Format {
            context: CONFIG_FILE.into(),
            detail: format!("{}", e),
        })
    }

    pub fn save(&self, p: &Platform) -> Result<(), LatchError> {
        // Refuse to persist anything secret-shaped (A-series guarantee):
        // the config is plaintext by design and must stay boring.
        for proj in &self.projects {
            if proj.name.len() > 64 || proj.name.contains(['\n', '=']) {
                return Err(LatchError::other(
                    format!("suspicious project name {:?}", proj.name),
                    "project names are short identifiers; secrets belong in the credential store",
                ));
            }
        }
        // S2: the repo string reaches `git clone` as a URL. Backups and
        // clone payloads set it WITHOUT going through login's validation,
        // so guard it here — the last gate before it hits disk and, next
        // command, git's argv. git's ext::/fd:: transports execute
        // commands, so a scheme other than https/file is a code-exec risk.
        if let Some(repo) = &self.repo {
            validate_repo(repo)?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| LatchError::Format {
            context: CONFIG_FILE.into(),
            detail: format!("encode: {}", e),
        })?;
        p.files.write_atomic(&Self::path(p), text.as_bytes())
    }

    pub fn project_for_dir(&self, dir: &str) -> Option<&Project> {
        self.projects
            .iter()
            .find(|pr| dir == pr.dir || dir.starts_with(&format!("{}/", pr.dir)))
    }
}

/// S2: accept only repo strings that cannot turn `git clone` into command
/// execution. Either the plain `owner/name` form (login expands it to an
/// https URL), or an explicit `https://` / `file://` URL — never git's
/// `ext::`/`fd::`/`ssh://`-with-options transports.
pub fn validate_repo(repo: &str) -> Result<(), LatchError> {
    let bad = |detail: &str| {
        Err(LatchError::other(
            format!("refusing repo '{}': {}", repo, detail),
            "use 'owner/name' or an https:// / file:// URL — other git transports can execute commands",
        ))
    };
    if repo.is_empty() || repo.contains(['\n', '\r', '\0']) || repo.starts_with('-') {
        return bad("empty, control chars, or leading dash");
    }
    if repo.contains("://") {
        if !(repo.starts_with("https://") || repo.starts_with("file://")) {
            return bad("only https:// and file:// URLs are allowed");
        }
        return Ok(());
    }
    // owner/name: exactly one slash, no scheme-ish colon.
    if repo.split('/').count() != 2 || repo.contains(':') || repo.split('/').any(|p| p.is_empty()) {
        return bad("not a valid owner/name");
    }
    Ok(())
}
