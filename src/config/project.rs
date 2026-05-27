use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Contents of `.latch/config.toml` committed inside a project repository.
/// Contains no secrets – only metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub secrets_repo: String,
    #[serde(default = "default_env")]
    pub default_env: String,
}

fn default_env() -> String {
    "dev".to_string()
}

impl ProjectConfig {
    /// Write `.latch/config.toml` relative to `root`.
    pub fn save_in(&self, root: &Path) -> Result<()> {
        let dir = root.join(".latch");
        std::fs::create_dir_all(&dir)?;
        let text = toml::to_string_pretty(self).context("Serialising project config")?;
        std::fs::write(dir.join("config.toml"), text)?;
        Ok(())
    }

    /// Walk upward from `start` to find the nearest `.latch/config.toml`.
    pub fn find_and_load(start: &Path) -> Result<(Self, PathBuf)> {
        let mut dir = start.to_path_buf();
        loop {
            let candidate = dir.join(".latch").join("config.toml");
            if candidate.exists() {
                let text = std::fs::read_to_string(&candidate)
                    .with_context(|| format!("Reading {}", candidate.display()))?;
                let cfg: Self = toml::from_str(&text)
                    .with_context(|| format!("Parsing {}", candidate.display()))?;
                // Return config + the project root (the dir that contains .latch/)
                return Ok((cfg, dir));
            }
            match dir.parent() {
                Some(parent) => dir = parent.to_path_buf(),
                None => bail!(
                    "No .latch/config.toml found. Run 'latch init' in your project root."
                ),
            }
        }
    }
}
