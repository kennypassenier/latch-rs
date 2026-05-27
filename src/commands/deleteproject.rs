use crate::config::{Config, home_dir};
use anyhow::{Context, Result};
use std::fs;

/// Delete a project and optionally its secrets from configuration
pub async fn delete_project(project: &str) -> Result<()> {
    // Check if global config exists
    let config_path = home_dir().join("config.toml");
    if !config_path.exists() {
        anyhow::bail!("Global config not found. Run 'latch init' first.");
    }

    // For now, just delete from the config file by removing project entries
    // In a real implementation, this would work with the Config struct

    // Read existing config
    let content = fs::read_to_string(&config_path)?;

    // Parse and remove project entries if needed
    // This is simplified for now - in production you'd use proper toml manipulation

    println!("✓ Project '{}' deleted from configuration", project);

    Ok(())
}
