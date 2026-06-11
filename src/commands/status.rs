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

#[derive(Debug)]
enum FileStatus {
    InSync,
    Modified,
    Missing,
    Error(String),
}

pub async fn run(env_name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env_name))?;
    let key = parse_key(&key_hex)?;
    let fp = {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(key);
        format!("fp:{}", hex::encode(&d[..6]))
    };
    println!(
        "Key {} (from project '{}' env '{}')\n",
        fp, cfg.name, env_name
    );
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github
        .pull_file(&manifest_path)
        .await
        .map_err(|_| anyhow::anyhow!("manifest.json not found. Run 'latch init' first."))?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env_name);
    let groups: Vec<_> = manifest
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .collect();

    if mappings.is_empty() && groups.is_empty() {
        println!(
            "No files tracked for env '{}'. Run 'latch push --env {}' first.",
            env_name, env_name
        );
        return Ok(());
    }

    println!("Status for project '{}' / env '{}'\n", cfg.name, env_name);

    let mut any_out_of_sync = false;

    for mapping in mappings {
        let rel_path = std::path::Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env_name, &flat);
        let local_abs = project_root.join(rel_path);

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
            FileStatus::InSync => ("OK", "in sync "),
            FileStatus::Modified => ("~", "modified"),
            FileStatus::Missing => ("!", "missing "),
            FileStatus::Error(_) => ("X", "error   "),
        };

        match &status {
            FileStatus::Error(msg) => {
                println!("  {} {}  {}  ({})", icon, label, mapping.local_path, msg)
            }
            _ => println!("  {} {}  {}", icon, label, mapping.local_path),
        }

        if !matches!(status, FileStatus::InSync) {
            any_out_of_sync = true;
        }
    }

    if !groups.is_empty() {
        println!("\nClone groups:\n");
        for group in &groups {
            let mut group_ok = true;
            let remote_plain = match github.pull_file(&group.remote_blob).await {
                Err(e) => {
                    println!("  X group:{}  error ({})", group.name, e);
                    any_out_of_sync = true;
                    continue;
                }
                Ok(ciphertext) => match decrypt(&ciphertext, &key) {
                    Err(e) => {
                        println!("  X group:{}  decrypt failed ({})", group.name, e);
                        any_out_of_sync = true;
                        continue;
                    }
                    Ok(plain) => plain,
                },
            };

            for member in &group.members {
                let local_abs = project_root.join(member);
                if !local_abs.exists() {
                    group_ok = false;
                    break;
                }
                let local_bytes = std::fs::read(&local_abs)?;
                if local_bytes != remote_plain {
                    group_ok = false;
                    break;
                }
            }

            if group_ok {
                println!(
                    "  OK in sync   group:{} ({} members)",
                    group.name,
                    group.members.len()
                );
            } else {
                println!(
                    "  ~ modified  group:{} ({} members)",
                    group.name,
                    group.members.len()
                );
                any_out_of_sync = true;
            }
        }
    }

    if any_out_of_sync {
        println!("\nSome files are out of sync.");
        println!(
            "  Run 'latch push --env {}' to push local changes.",
            env_name
        );
        println!(
            "  Run 'latch pull --env {}' to pull remote changes.",
            env_name
        );
    } else {
        println!("\nAll files are in sync.");
    }

    Ok(())
}
