use super::*;
use crate::config::{Config, home_dir};
use anyhow::{Context, Result, bail};

/// Set up or update a project's configuration with GitHub PAT
pub async fn set_project(project: &str) -> Result<()> {
    // Check if global config exists
    let config_path = home_dir().join("config.toml");
    if !config_path.exists() {
        anyhow::bail!("Global config not found. Run 'latch init' first.");
    }

    println!("\n=== {} ===", project);
    println!("Set up your GitHub token for repository access:\n");

    // Prompt for encryption key
    let key_b64 = prompt_for_key()?;

    // Load existing config to preserve any settings
    let mut config = Config::load()?;

    // Store encrypted key and project info in global config
    config.set_global_project(project, &key_b64)?;

    println!("\n✓ Project '{}' configured", project);
    println!("  Encryption key saved locally");
    println!("  Run 'latch repo add' to register the secrets repository\n");

    Ok(())
}

/// Prompt user for encryption key (base64-encoded secret)
fn prompt_for_key() -> Result<Option<String>> {
    let mut input: String = dialoguer::Input::new()
        .with_prompt("Enter your secret (base64 or hex encoded)")
        .interact_text()?;

    // Check if user wants to remove key
    let clean_input = input.trim();
    if clean_input.is_empty() {
        return Ok(None);
    }

    // If it's all spaces or just whitespace, treat as "remove key"
    if clean_input.chars().all(|c| c == ' ') {
        return Ok(Some(" ".to_string()));
    }

    Ok(Some(clean_input.clone()))
}

/// Get the project name from environment variable or argument
pub fn get_project_from_env_or_arg() -> Result<String> {
    if let Ok(project) = std::env::var("LATCH_PROJECT") {
        return Ok(project);
    }

    Err(anyhow::anyhow!(
        "No project specified. Set LATCH_PROJECT env var or use 'latch <command> <project>'"
    ))
}
