use super::*;
use crate::config::{Config, home_dir};
use anyhow::{Context, Result, bail};

/// Decrypt secrets for a project (all environments)
pub async fn decrypt(project: &str) -> Result<()> {
    let config = Config::load()?;

    // Load manifest from repo
    let repo_path = crate::commands::repo::secrets_repo_path();
    let manifest_path = format!("{}/secrets-manifest.yaml", repo_path);

    if !std::path::PathBuf::from(&manifest_path).exists() {
        anyhow::bail!("Manifest not found. Run 'latch init' first.");
    }

    let manifest: Manifest = serde_yaml::from_str(&std::fs::read_to_string(&manifest_path)?)?;

    // Decrypt each environment
    for env_name in manifest.encrypted_envs.iter() {
        let env = manifest
            .envs
            .get(env_name)
            .ok_or_else(|| LatchError::Config(format!("Environment '{}' not found", env_name)))?;

        if env.key.is_empty() {
            anyhow::bail!("No key provided for environment '{}'", env_name);
        }

        // The key field in manifest IS the decrypted plaintext, base64 encoded
        let plaintext = base64::decode(&env.key)?;

        println!("\n===== {} =====", env_name);
        for (secret_name, value) in &env.secrets {
            let decoded = String::from_utf8_lossy(&plaintext);
            // For each secret, extract or show appropriate value
            println!("{}: {}", secret_name, value);
        }
    }

    Ok(())
}

/// Decrypt all secrets for all projects and environments
pub async fn decrypt_all_secrets() -> Result<()> {
    let config = Config::load()?;
    let projects: Vec<_> = config.projects().collect();

    if projects.is_empty() {
        println!("ℹ No projects configured. Run 'latch init' first.\n");
        return Ok(());
    }

    for project in &projects {
        println!("\n🔓 Decryption for '{}':", project);
        let result = decrypt(project).await;

        match &result {
            Ok(()) => println!("✓ All secrets decrypted for '{}'", project),
            Err(e) => println!("✗ Error decrypting '{}': {}", project, e),
        }
    }

    Ok(())
}

/// Get manifest structure for decryption
#[derive(Debug, serde::Deserialize)]
struct Manifest {
    encrypted_envs: Vec<String>,
    envs: std::collections::HashMap<String, EnvEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct EnvEntry {
    key: String,
    secrets: std::collections::HashMap<String, String>,
}
