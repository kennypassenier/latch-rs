/// Configuration management for the Latch CLI
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub mod global;
pub mod project;

/// Global configuration home directory
pub fn home_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".latch")
}

/// Find config path - returns anyhow error instead of LatchError for easier handling
fn find_config_path(project: &str) -> Result<PathBuf> {
    // First, look in the project's secrets repo (preferred location)
    let repo_path = crate::commands::repo::secrets_repo_path();
    if repo_path.exists() {
        let config_file = repo_path.join("latch.config.toml");
        if config_file.exists() {
            return Ok(config_file);
        }
    }

    // Fall back to ~/.latch/config.toml
    let global_config_path = home_dir().join("config.toml");
    if global_config_path.exists() {
        return Ok(global_config_path);
    }

    Err(anyhow::anyhow!(format!(
        "Latch config not found at {}. Run 'latch init <project>' to initialize.",
        repo_path.display()
    )))
}

/// Configuration structure
pub struct Config {
    global: Option<global::GlobalConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self { global: None }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        let config_path = find_config_path("load")?;
        let content = std::fs::read_to_string(&config_path)?;

        // For init/delete operations, we can work with the raw content
        Ok(Self { global: None })
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = find_config_path("save")?;

        if self.global.is_none() {
            // No config saved if nothing exists
            return Ok(());
        }

        use std::io::Write;
        let mut file = std::fs::File::create(&config_path)?;

        writeln!(&mut file, "[global]")?;

        let global = self.global.as_ref().context("No global config")?;
        writeln!(
            &mut file,
            "key_b64 = \"{}\"",
            global
                .key_b64
                .as_ref()
                .map(|s| s.replace('"', "\\\""))
                .unwrap_or_default()
        )?;
        if let Some(github_pat) = &global.github_pat {
            writeln!(&mut file, "github_pat = {}", github_pat)?;
        }

        Ok(())
    }

    /// Set up a project in global config (used during init/set-project)
    pub fn set_global_github_pat(&mut self, github_pat: &str) -> Result<()> {
        let mut global = match std::mem::replace(&mut self.global, None) {
            Some(g) => g,
            None => global::GlobalConfig::new(),
        };

        global.github_pat = Some(github_pat.to_string());
        self.global = Some(global);
        self.save()?;

        Ok(())
    }

    /// Get all configured projects (currently just returns "myproject")
    pub fn projects(&self) -> Vec<String> {
        vec!["myproject".to_string()]
    }

    /// Check if global config exists
    pub fn has_global_config(&self) -> bool {
        self.global.is_some()
    }

    /// Get the global config (for internal use during init/delete)
    pub fn get_global_mut(&mut self) -> Result<&mut global::GlobalConfig> {
        let global = match &mut self.global {
            Some(g) => g,
            None => return Err(anyhow::anyhow!("No global config")),
        };

        Ok(global)
    }

    /// Parse existing config from text and update current config
    pub fn parse(&mut self, config_text: &str) -> Result<()> {
        // Remove whitespace-only lines and trim trailing newlines
        let trimmed = config_text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        if trimmed.is_empty() {
            return Ok(());
        }

        // Extract github_pat from the config text (simple string search)
        let pat: String = if let Some(start) = trimmed.find("github_pat = ") {
            let pat_part = &trimmed[start + "github_pat = ".len()..];
            // Extract until we hit a newline or comment
            if let Some(end) = pat_part.find('\n') | pat_part.find('=') {
                pat_part[..end].trim().to_string()
            } else {
                pat_part.trim().to_string()
            }
        } else {
            String::new()
        };

        let mut global = match self.global.take() {
            Some(g) => g,
            None => global::GlobalConfig::new(),
        };

        if !pat.is_empty() {
            global.github_pat = Some(pat);
        }

        self.global = Some(global);
        Ok(())
    }
}
