use anyhow::Result;
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

/// Change status of a single file.
#[derive(Debug)]
enum FileStatus {
    /// Local file matches the remote encrypted payload.
    InSync,
    /// Local file exists but differs from the remote.
    Modified,
    /// Remote file exists but no local file was found.
    Missing,
    /// Decryption failed — likely a key mismatch or corrupt payload.
    Error(String),
}

pub async fn run(env: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env))?;
    let key = parse_key(&key_hex)?;
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // ── Fetch manifest ────────────────────────────────────────────────────────
    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github
        .pull_file(&manifest_path)
        .await
        .map_err(|_| anyhow::anyhow!("manifest.json not found. Run 'latch init' first."))?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env);
    if mappings.is_empty() {
        println!(
            "No files tracked for env '{}'. Run 'latch save --env {}' first.",
            env, env
        );
        return Ok(());
    }

    println!("Status for project '{}' / env '{}'\n", cfg.name, env);

    let mut any_out_of_sync = false;

    for mapping in mappings {
        let rel_path = std::path::Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env, &flat);
        let local_abs = project_root.join(rel_path);

        // Determine status
        let status = match github.pull_file(&remote).await {
            Err(e) => FileStatus::Error(e.to_string()),
            Ok(ciphertext) => match decrypt(&ciphertext, &key) {
                Err(e) => FileStatus::Error(e.to_string()),
                Ok(remote_plain) => {
                    if local_abs.exists() {
                        let local_bytes = std::fs::read(&local_abs)?;
                        if local_bytes == remote_plain {
                            FileStatus::InSync
                        } else {
                            FileStatus::Modified
                        }
                    } else {
                        FileStatus::Missing
                    }
                }
            },
        };

        let (icon, label) = match &status {
            FileStatus::InSync => ("✓", "in sync "),
            FileStatus::Modified => ("~", "modified"),
            FileStatus::Missing => ("!", "missing "),
            FileStatus::Error(_) => ("✗", "error   "),
        };

        match &status {
            FileStatus::Error(msg) => {
                println!("  {} {}  {}  ({})", icon, label, mapping.local_path, msg);
            }
            _ => println!("  {} {}  {}", icon, label, mapping.local_path),
        }

        if !matches!(status, FileStatus::InSync) {
            any_out_of_sync = true;
        }
    }

    println!();
    if any_out_of_sync {
        println!("Some files are out of sync.");
        println!("  Run 'latch save  --env {}' to push local changes.", env);
        println!("  Run 'latch load --env {}' to pull remote changes.", env);
    } else {
        println!("All files are in sync.");
    }

    Ok(())
}
