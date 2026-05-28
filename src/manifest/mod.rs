use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Data model ────────────────────────────────────────────────────────────────

/// A single encrypted-file mapping stored inside the manifest.
///
/// `local_path` is the path relative to the project root, e.g. `backend/.env`.
/// The corresponding remote path is derived at runtime via
/// [`crate::discovery::remote_path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMapping {
    /// Path to the plaintext file, relative to the project root.
    pub local_path: String,
}

/// Top-level manifest stored as `{project}/manifest.json` in the secrets repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version – currently always `1`.
    pub version: u32,
    /// Project name (must match the folder under which it is stored).
    pub project: String,
    /// Base64-encoded Argon2 salt used when the project was initialised in
    /// passphrase mode.  `None` for raw-key mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// Map of environment name → list of file mappings.
    /// E.g. `{ "dev": [...], "prod": [...] }`.
    pub envs: HashMap<String, Vec<FileMapping>>,
}

impl Manifest {
    /// Create a blank manifest for `project`.
    pub fn new(project: &str, kdf_salt: Option<String>) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            kdf_salt,
            envs: HashMap::new(),
        }
    }

    /// Remote path of the manifest file itself inside the secrets repo.
    pub fn remote_path(project: &str) -> String {
        format!("{}/manifest.json", project)
    }

    /// Serialise to pretty-printed JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_string_pretty(self).context("Serialising manifest")?;
        Ok(json.into_bytes())
    }

    /// Deserialise from raw JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("Parsing manifest JSON")
    }

    /// Return the mappings for `env`, defaulting to an empty slice.
    pub fn get_env(&self, env: &str) -> &[FileMapping] {
        self.envs.get(env).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Replace the mapping list for `env` with `files`.
    pub fn set_env(&mut self, env: &str, files: Vec<FileMapping>) {
        self.envs.insert(env.to_string(), files);
    }
}
