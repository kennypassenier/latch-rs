pub mod env_provider;
pub mod keyring_provider;

use anyhow::Result;

/// Abstraction over how credentials are obtained.
/// Implementations: [`KeyringProvider`], [`EnvVarProvider`].
/// Use [`resolve`] to walk the full fallback chain.
pub trait CredentialProvider: Send + Sync {
    /// GitHub Personal Access Token, or `None` if unavailable.
    fn get_pat(&self, project: &str) -> Option<String>;

    /// Raw encryption key (hex-encoded 32 bytes), or `None` if unavailable.
    fn get_key(&self, project: &str) -> Option<String>;

    /// Persist credentials.  Not all providers support writing.
    fn set_credentials(&self, project: &str, pat: Option<&str>, key: Option<&str>) -> Result<()>;

    /// Remove stored credentials.  Not all providers support deletion.
    #[allow(dead_code)]
    fn delete_credentials(&self, project: &str) -> Result<()>;
}

// ── Fallback chain ────────────────────────────────────────────────────────────

use crate::config::global::GlobalConfig;
use env_provider::EnvVarProvider;
use keyring_provider::KeyringProvider;

pub const GLOBAL_PAT_SLOT: &str = "github.pat";
pub const GLOBAL_SECRETS_REPO_SLOT: &str = "github.secrets_repo";

pub fn get_global_pat() -> Option<String> {
    KeyringProvider::get_raw(GLOBAL_PAT_SLOT)
}

pub fn set_global_pat(pat: &str) -> Result<()> {
    KeyringProvider::set_raw(GLOBAL_PAT_SLOT, pat)
}

pub fn get_global_secrets_repo() -> Option<String> {
    KeyringProvider::get_raw(GLOBAL_SECRETS_REPO_SLOT)
}

pub fn set_global_secrets_repo(repo: &str) -> Result<()> {
    KeyringProvider::set_raw(GLOBAL_SECRETS_REPO_SLOT, repo)
}

/// Try providers in order: OS keyring → env vars → `~/.latch/config.toml`.
/// Returns the first non-`None` value for each credential.
pub struct FallbackChain {
    project: String,
}

impl FallbackChain {
    pub fn new(project: &str) -> Self {
        Self {
            project: project.to_string(),
        }
    }

    /// Returns the hex-encoded 32-byte key or an error with a helpful message.
    ///
    /// Uses the default (project-wide) key slot.  Provided as a convenience;
    /// prefer [`get_key_for_env`] when an env name is available.
    #[allow(dead_code)]
    pub fn get_key(&self) -> Result<String> {
        self.get_key_for_env(None)
    }

    /// Returns the key for a specific environment (8.5 multi-key support).
    ///
    /// Look-up order:
    /// 1. OS keyring slot `"{project}.key.{env}"`  (env-specific override)
    /// 2. OS keyring slot `"{project}.key"`         (project-wide default)
    /// 3. `LATCH_KEY` environment variable
    /// 4. `key_hex` in `~/.latch/config.toml`
    pub fn get_key_for_env(&self, env: Option<&str>) -> Result<String> {
        let keyring = KeyringProvider;
        let env_provider = EnvVarProvider;

        // 1. env-specific keyring slot
        if let Some(env_name) = env {
            let slot = format!("{}.key.{}", self.project, env_name);
            if let Some(k) = KeyringProvider::get_raw(&slot) {
                return Ok(k);
            }
        }
        // 2. project-wide keyring slot
        if let Some(k) = keyring.get_key(&self.project) {
            return Ok(k);
        }
        // 3. env var
        if let Some(k) = env_provider.get_key(&self.project) {
            return Ok(k);
        }
        // 4. config-file fallback
        if let Ok(global) = GlobalConfig::load() {
            if let Some(entry) = global.get_project(&self.project) {
                if let Some(k) = &entry.key_hex {
                    return Ok(k.clone());
                }
            }
        }
        anyhow::bail!(
            "No encryption key found for project '{}'. \
             Run 'latch init', set LATCH_KEY, or add key_hex to ~/.latch/config.toml.",
            self.project
        )
    }

    /// Store an environment-specific key in the OS keyring (8.5).
    pub fn set_key_for_env(&self, env: &str, key_hex: &str) -> Result<()> {
        let slot = format!("{}.key.{}", self.project, env);
        KeyringProvider::set_raw(&slot, key_hex)
    }

    /// Returns the GitHub PAT or an error with a helpful message.
    pub fn get_pat(&self) -> Result<String> {
        let keyring = KeyringProvider;
        let env = EnvVarProvider;

        if let Some(p) = get_global_pat() {
            return Ok(p);
        }
        if let Some(p) = keyring.get_pat(&self.project) {
            return Ok(p);
        }
        if let Some(p) = env.get_pat(&self.project) {
            return Ok(p);
        }
        if let Ok(global) = GlobalConfig::load() {
            if let Some(entry) = global.get_project(&self.project) {
                if let Some(p) = &entry.github_pat {
                    return Ok(p.clone());
                }
            }
        }
        anyhow::bail!(
            "No GitHub PAT found for project '{}'. \
             Run 'latch init', set LATCH_PAT, or add github_pat to ~/.latch/config.toml.",
            self.project
        )
    }

    /// Remove the default project key and PAT from the OS keyring.
    ///
    /// A missing entry is treated as success (idempotent).
    #[allow(dead_code)]
    pub fn clear_project_credentials(&self) -> Result<()> {
        KeyringProvider::delete_raw(&format!("{}.key", self.project))?;
        KeyringProvider::delete_raw(&format!("{}.pat", self.project))?;
        Ok(())
    }

    /// Remove the env-specific key slot from the OS keyring.
    #[allow(dead_code)]
    pub fn delete_key_for_env(&self, env: &str) -> Result<()> {
        let slot = format!("{}.key.{}", self.project, env);
        KeyringProvider::delete_raw(&slot)
    }
}
