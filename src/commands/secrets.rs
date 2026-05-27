use anyhow::{Context, Result};
use std::fs;

/// Manifest structure for secrets management
#[derive(Debug, serde::Deserialize)]
struct Manifest {
    envs: std::collections::HashMap<String, EnvEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct EnvEntry {
    key: String,
    secrets: std::collections::HashMap<String, String>,
}

/// Add a new secret to an environment
pub async fn add_secret(
    _project: &str,
    repo_path: &std::path::PathBuf,
    env: &str,
    key: &str,
    value: String,
) -> Result<()> {
    // Load manifest from repo
    let manifest_path = repo_path.join("secrets-manifest.yaml");

    if !repo_path.exists(&manifest_path) {
        anyhow::bail!("Manifest not found. Run 'latch init' first.");
    }

    let content = fs::read_to_string(&manifest_path)?;
    let mut manifest: Manifest = serde_yaml::from_str(&content)?;

    // Find or create the environment entry
    if let Some(env_entry) = manifest.envs.get_mut(env) {
        env_entry.secrets.insert(key.to_string(), value);

        println!("✓ Secret '{}' added to environment '{}'", key, env);
    } else {
        anyhow::bail!("Environment '{}' not found", env);
    }

    // Commit and push manifest changes
    let repo_path_str = repo_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    crate::commands::repo::commit_with_message(
        repo_path_str,
        &format!("Add secret {} to {}", key, env),
    )?;

    Ok(())
}

/// List all secrets for an environment in a project
pub async fn list_secrets(_project: &str, repo_path: &std::path::PathBuf, env: &str) -> Result<()> {
    let manifest_path = repo_path.join("secrets-manifest.yaml");

    if !repo_path.exists(&manifest_path) {
        anyhow::bail!("Manifest not found. Run 'latch init' first.");
    }

    let content = fs::read_to_string(&manifest_path)?;
    let manifest: Manifest = serde_yaml::from_str(&content)?;

    let env_entry = manifest.envs.get(env).context("Environment not found")?;

    println!("\n📋 Environment: {}", env);
    if !env_entry.secrets.is_empty() {
        for (secret_name, value) in &env_entry.secrets {
            println!("  • {}: {}", secret_name, value);
        }
    } else {
        println!("  ℹ No secrets configured");
    }

    Ok(())
}

/// Get a specific secret's encrypted value
pub async fn get_secret(
    _project: &str,
    _github_pat: Option<&str>,
    repo_path: &std::path::PathBuf,
    env: &str,
    key: &str,
) -> Result<()> {
    let manifest_path = repo_path.join("secrets-manifest.yaml");

    if !repo_path.exists(&manifest_path) {
        anyhow::bail!("Manifest not found. Run 'latch init' first.");
    }

    let content = fs::read_to_string(&manifest_path)?;
    let manifest: Manifest = serde_yaml::from_str(&content)?;

    let env_entry = manifest.envs.get(env).context("Environment not found")?;

    let encrypted_value = env_entry
        .secrets
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Secret '{}' not found", key))?;

    println!("{}", encrypted_value);

    Ok(())
}

/// Delete a secret from an environment
pub async fn delete_secret(
    _project: &str,
    repo_path: &std::path::PathBuf,
    env: &str,
    key: &str,
) -> Result<()> {
    let manifest_path = repo_path.join("secrets-manifest.yaml");

    if !repo_path.exists(&manifest_path) {
        anyhow::bail!("Manifest not found. Run 'latch init' first.");
    }

    let mut content = fs::read_to_string(&manifest_path)?;
    let mut manifest: Manifest = serde_yaml::from_str(&content.as_str())?;

    let env_entry = manifest
        .envs
        .get_mut(env)
        .context("Environment not found")?;

    if env_entry.secrets.remove(key).is_some() {
        println!("✓ Secret '{}' deleted from environment '{}'", key, env);
    } else {
        anyhow::bail!("Secret '{}' not found", key);
    }

    // Write back the updated manifest
    fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;

    // Commit and push manifest changes
    let repo_path_str = repo_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    crate::commands::repo::commit_with_message(
        repo_path_str,
        &format!("Remove secret {} from {}", key, env),
    )?;

    Ok(())
}
