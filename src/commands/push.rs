use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::path::Path;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, local_blob_path, local_group_blob_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("fp:{}", hex::encode(&digest[..6]))
}

pub async fn run(env_name: &str, force: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    // ── Load staging manifest ─────────────────────────────────────────────────
    let staging = Manifest::load_staging(&project_root)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Nothing staged. Run 'latch commit --env {}' first.",
            env_name
        )
    })?;

    // ── Connect to GitHub ─────────────────────────────────────────────────────
    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;
    let key_hex = chain.get_key_for_env(Some(env_name))?;
    let verify_key = parse_key(&key_hex)?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // ── Pre-upload: verify every local blob decrypts with the current key ─────
    // Local verification avoids GitHub API caching false-negatives.
    let mut pre_verify_failed: Vec<String> = Vec::new();
    for mapping in staging.get_env(env_name) {
        let flat = flatten_path(Path::new(&mapping.local_path));
        let local_blob = local_blob_path(&project_root, env_name, &flat);
        if local_blob.exists() {
            let ct = std::fs::read(&local_blob)?;
            if decrypt(&ct, &verify_key).is_err() {
                pre_verify_failed.push(mapping.local_path.clone());
            }
        } else {
            pre_verify_failed.push(format!(
                "{} (blob missing — re-run commit)",
                mapping.local_path
            ));
        }
    }
    for group in staging.clone_groups.iter().filter(|g| g.env == env_name) {
        let local_blob = local_group_blob_path(&project_root, env_name, &group.name);
        if local_blob.exists() {
            let ct = std::fs::read(&local_blob)?;
            if decrypt(&ct, &verify_key).is_err() {
                pre_verify_failed.push(format!("group:{}", group.name));
            }
        } else {
            pre_verify_failed.push(format!(
                "group:{} (blob missing — re-run commit)",
                group.name
            ));
        }
    }
    if !pre_verify_failed.is_empty() {
        anyhow::bail!(
            "Local blob verification FAILED for {} file(s) using key {}.\n\
             Run 'latch commit' to re-encrypt, then retry:\n  {}",
            pre_verify_failed.len(),
            key_fingerprint(&verify_key),
            pre_verify_failed.join("\n  ")
        );
    }
    println!(
        "Local blobs OK (key {}) — uploading to {}",
        key_fingerprint(&verify_key),
        cfg.secrets_repo
    );

    // Fetch the remote manifest.
    let manifest_path = Manifest::remote_path(&cfg.name);
    let mut remote_manifest = match github.get_sha(&manifest_path).await? {
        Some(_) => Manifest::from_bytes(&github.pull_file(&manifest_path).await?)?,
        None => Manifest::new(&cfg.name, staging.kdf_salt.clone()),
    };

    let previous_mappings = remote_manifest.get_env(env_name).to_vec();
    let previous_groups: Vec<_> = remote_manifest
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .cloned()
        .collect();

    let staged_mappings = staging.get_env(env_name);
    let staged_groups: Vec<_> = staging
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .collect();

    if staged_mappings.is_empty()
        && staged_groups.is_empty()
        && previous_mappings.is_empty()
        && previous_groups.is_empty()
    {
        println!(
            "Environment '{}' has no staged files and remote is already empty; nothing to push.",
            env_name
        );
        return Ok(());
    }

    // ── If --force: delete ALL existing remote blobs for this env first ───────
    if force {
        println!(
            "Force mode: deleting all existing remote blobs for env '{}' before upload...",
            env_name
        );
        let prefix = format!("{}/{}/", cfg.name, env_name);
        match github.list_files(&prefix).await {
            Ok(existing) => {
                for path in existing {
                    github
                        .delete_file(
                            &path,
                            &format!("latch: force-clear {} [{}]", env_name, cfg.name),
                        )
                        .await?;
                }
            }
            Err(e) => println!("  (could not list remote blobs for cleanup: {})", e),
        }
    }

    // ── Upload staged blobs ───────────────────────────────────────────────────
    let total_ops = staged_mappings.len() + staged_groups.len();
    println!(
        "Pushing {} staged file(s) ({} standalone, {} group(s)) to {} (env: {})",
        staged_mappings.len() + staged_groups.iter().map(|g| g.members.len()).sum::<usize>(),
        staged_mappings.len(),
        staged_groups.len(),
        cfg.secrets_repo,
        env_name
    );

    let pb = ProgressBar::new(total_ops as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    for mapping in staged_mappings {
        let rel = Path::new(&mapping.local_path);
        let flat = flatten_path(rel);
        let remote = remote_path(&cfg.name, env_name, &flat);
        let local_blob = local_blob_path(&project_root, env_name, &flat);

        if !local_blob.exists() {
            anyhow::bail!(
                "Staged blob missing: {}. Re-run 'latch commit --env {}'.",
                local_blob.display(),
                env_name
            );
        }

        pb.set_message(format!("{}", rel.display()));
        let ciphertext = std::fs::read(&local_blob)?;
        github
            .push_file(
                &remote,
                &ciphertext,
                &format!("latch: push {} [{}]", env_name, cfg.name),
            )
            .await?;
        pb.inc(1);
    }

    for group in &staged_groups {
        let local_blob = local_group_blob_path(&project_root, env_name, &group.name);

        if !local_blob.exists() {
            anyhow::bail!(
                "Staged group blob missing: {}. Re-run 'latch commit --env {}'.",
                local_blob.display(),
                env_name
            );
        }

        pb.set_message(format!("group:{}", group.name));
        let ciphertext = std::fs::read(&local_blob)?;
        github
            .push_file(
                &group.remote_blob,
                &ciphertext,
                &format!("latch: push {} [{}]", env_name, cfg.name),
            )
            .await?;
        pb.inc(1);
    }

    pb.finish_with_message("All files uploaded");

    // ── Clean up remote files no longer staged ────────────────────────────────
    let new_paths: HashSet<&str> = staging
        .get_env(env_name)
        .iter()
        .map(|m| m.local_path.as_str())
        .collect();
    for old in &previous_mappings {
        if !new_paths.contains(old.local_path.as_str()) {
            let flat = flatten_path(Path::new(&old.local_path));
            let remote = remote_path(&cfg.name, env_name, &flat);
            github
                .delete_file(&remote, &format!("latch: push {} [{}]", env_name, cfg.name))
                .await?;
        }
    }

    let new_group_names: HashSet<&str> = staged_groups.iter().map(|g| g.name.as_str()).collect();
    for old_group in &previous_groups {
        if !new_group_names.contains(old_group.name.as_str()) {
            github
                .delete_file(
                    &old_group.remote_blob,
                    &format!("latch: push {} [{}]", env_name, cfg.name),
                )
                .await?;
        }
    }

    // ── Update remote manifest ────────────────────────────────────────────────
    remote_manifest.set_env(env_name, staging.get_env(env_name).to_vec());
    remote_manifest.clone_groups.retain(|g| g.env != env_name);
    remote_manifest
        .clone_groups
        .extend(staged_groups.iter().map(|g| (*g).clone()));
    if let Some(salt) = &staging.kdf_salt {
        remote_manifest.kdf_salt = Some(salt.clone());
    }

    let total_files = remote_manifest.get_env(env_name).len()
        + remote_manifest
            .clone_groups
            .iter()
            .filter(|g| g.env == env_name)
            .count();
    github
        .push_file(
            &manifest_path,
            &remote_manifest.to_bytes()?,
            &format!(
                "latch: push {} ({} files) [{}]",
                env_name, total_files, cfg.name
            ),
        )
        .await?;

    println!("Manifest updated.");
    println!(
        "\nAll done! Pull on another machine with: latch pull --env {}",
        env_name
    );
    Ok(())
}
