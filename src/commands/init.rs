use crate::commands::{decrypt::decrypt_all_secrets, repo::secrets_repo_path};
use crate::config::{Config, home_dir};
use anyhow::Context;

/// Initialize a new project with its secrets repository configuration
pub async fn init_project(project: &str) -> anyhow::Result<()> {
    let repo_path = secrets_repo_path().context("Could not get secrets repo path")?;

    // Create the parent directory for secrets if needed
    let parent = repo_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid project name (no path separator)"))?;

    std::fs::create_dir_all(parent).context("Failed to create secrets repo directory")?;

    // Create a new encrypted key if it doesn't exist at the default location
    let default_key_path = home_dir().join("key.bin");

    if default_key_path.exists() {
        // Key exists - copy it to the secrets repo
        let repo_key_path = repo_path.join("key.bin");
        std::fs::copy(&default_key_path, &repo_key_path)
            .context("Failed to copy encryption key")?;

        return Ok(());
    } else {
        // Key doesn't exist - bail out with an error
        anyhow::bail!("No encryption key found. Run 'latch key set' first.");
    }
}
