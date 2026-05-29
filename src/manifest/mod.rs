use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

/// A clone group: multiple local `.env` files that share one remote encrypted blob.
///
/// Group membership is declared by placing `# latch:group=<name>` as the very
/// first line of each member file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneGroup {
    /// Group name — matches the `# latch:group=<name>` pragma value.
    pub name: String,
    /// Environment this group belongs to (e.g. `dev`, `prod`).
    pub env: String,
    /// Remote path of the single shared encrypted blob.
    ///
    /// Format: `{project}/{env}/group.{name}.enc`
    pub remote_blob: String,
    /// Local paths (relative to the project root) of all member files.
    pub members: Vec<String>,
}

impl CloneGroup {
    /// Build the remote blob path for a clone group.
    ///
    /// Format: `{project}/{env}/group.{name}.enc`
    pub fn remote_blob_path(project: &str, env: &str, group_name: &str) -> String {
        format!("{}/{}/group.{}.enc", project, env, group_name)
    }
}

/// Top-level manifest stored as `{project}/manifest.json` in the secrets repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version – currently always `1`.
    pub version: u32,
    /// Project name (must match the folder under which it is stored).
    pub project: String,
    /// Base64-encoded Argon2 salt used when the project was initialised in
    /// passphrase mode. `None` for raw-key mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// Map of environment name → list of standalone file mappings.
    /// E.g. `{ "dev": [...], "prod": [...] }`.
    pub envs: HashMap<String, Vec<FileMapping>>,
    /// Clone groups tracked for this project (across all envs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clone_groups: Vec<CloneGroup>,
}

impl Manifest {
    /// Create a blank manifest for `project`.
    pub fn new(project: &str, kdf_salt: Option<String>) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            kdf_salt,
            envs: HashMap::new(),
            clone_groups: Vec::new(),
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

    /// Find a clone group by name and env.
    pub fn get_group(&self, name: &str, env: &str) -> Option<&CloneGroup> {
        self.clone_groups
            .iter()
            .find(|g| g.name == name && g.env == env)
    }

    /// Return the clone group that `local_path` belongs to, if any.
    pub fn group_for_member(&self, local_path: &str) -> Option<&CloneGroup> {
        self.clone_groups
            .iter()
            .find(|g| g.members.iter().any(|m| m == local_path))
    }

    // ── Local staging helpers ─────────────────────────────────────────────────

    /// Absolute path to the local staging manifest: `<project_root>/.latch/staging.json`.
    pub fn local_staging_path(project_root: &Path) -> PathBuf {
        project_root.join(".latch").join("staging.json")
    }

    /// Load the staging manifest from `.latch/staging.json`.
    /// Returns `None` if the staging area has not been initialised yet.
    pub fn load_staging(project_root: &Path) -> Result<Option<Self>> {
        let path = Self::local_staging_path(project_root);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).context("Reading .latch/staging.json")?;
        Ok(Some(Self::from_bytes(&bytes)?))
    }

    /// Persist the manifest to `.latch/staging.json`, creating the directory if needed.
    pub fn save_staging(&self, project_root: &Path) -> Result<()> {
        let path = Self::local_staging_path(project_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Creating .latch directory")?;
        }
        std::fs::write(&path, self.to_bytes()?).context("Writing .latch/staging.json")?;
        Ok(())
    }
}
