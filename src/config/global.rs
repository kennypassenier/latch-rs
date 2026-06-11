use crate::config::latch_home;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A project entry stored inside `~/.latch/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectEntry {
    pub name: String,
    pub secrets_repo: String,
    pub default_env: String,
    /// Fallback key (keyring is primary). Hex-encoded 32 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
    /// Fallback PAT (keyring is primary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_pat: Option<String>,
}

/// Top-level structure of `~/.latch/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    /// Machine-wide default secrets repo (`owner/repo`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_secrets_repo: Option<String>,
    /// Machine-wide PAT fallback when keyring is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_pat: Option<String>,
    /// Machine-wide encryption key fallback (hex-encoded 32 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_key_hex: Option<String>,
    #[serde(default)]
    pub projects: Vec<ProjectEntry>,
}

impl GlobalConfig {
    /// Path to the global config file.
    pub fn path() -> PathBuf {
        latch_home().join("config.toml")
    }

    /// Load from disk, returning an empty config if the file doesn't exist yet.
    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("Parsing {}", path.display()))
    }

    /// Persist to disk, creating `~/.latch/` if needed.
    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let text = toml::to_string_pretty(self).context("Serialising global config")?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Upsert a project entry (match on `name`).
    pub fn upsert_project(&mut self, entry: ProjectEntry) {
        if let Some(existing) = self.projects.iter_mut().find(|p| p.name == entry.name) {
            *existing = entry;
        } else {
            self.projects.push(entry);
        }
    }

    /// Look up a project by name.
    pub fn get_project(&self, name: &str) -> Option<&ProjectEntry> {
        self.projects.iter().find(|p| p.name == name)
    }
}
