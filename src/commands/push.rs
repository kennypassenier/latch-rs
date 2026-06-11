use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::env;
use std::path::Path;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    discovery::{flatten_path, local_blob_path, local_group_blob_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run(env_name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    // ── Load staging manifest ─────────────────────────────────────────────────
    let staging = Manifest::load_staging(&project_root)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Nothing staged. Run 'latch commit --env {}' first.",
            env_name
        )
    })?;

    let staged_mappings = staging.get_env(env_name);
    let staged_groups: Vec<_> = staging
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .collect();

    // ── Connect to GitHub (PAT only — no encryption key needed) ──────────────
    let pat = FallbackChain::new(&cfg.name).get_pat()?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // Fetch the remote manifest so we can clean up files removed since last push.
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
