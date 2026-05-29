use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::{env, path::Path};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    discovery::{flatten_path, remote_path},
    github::{RemoteStorage as _, RemoteStorageExt as _, client::GitHubClient},
    manifest::Manifest,
};

/// `latch rollback [--env <env>] [--to <sha>] [--steps <n>]`
///
/// Restores a previous save state by re-pushing old encrypted blobs to the
/// current HEAD as a new forward commit.  History is never rewritten.
pub async fn run(env_name: &str, to_sha: Option<&str>, steps: usize) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _project_root) = ProjectConfig::find_and_load(&cwd)?;
    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);

    // ── Resolve target commit SHA ─────────────────────────────────────────────
    let target_sha = if let Some(sha) = to_sha {
        sha.to_string()
    } else {
        let commits = github.list_commits(&manifest_path, steps + 1).await?;
        if commits.len() <= steps {
            anyhow::bail!(
                "Not enough history to go back {} step(s). Only {} commit(s) found for this project.\nRun 'latch history' to see available commits.",
                steps,
                commits.len()
            );
        }
        commits[steps].sha.clone()
    };

    let short_sha = &target_sha[..target_sha.len().min(8)];
    println!(
        "Rolling back project '{}' / env '{}' to commit {}…",
        cfg.name, env_name, short_sha
    );

    // ── Pull old manifest at target SHA ───────────────────────────────────────
    let old_manifest_bytes = github
        .pull_file_at_ref(&manifest_path, &target_sha)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Could not fetch manifest at commit {}: {}\nUse 'latch history' to list valid commits.",
                short_sha,
                e
            )
        })?;
    let old_manifest = Manifest::from_bytes(&old_manifest_bytes)?;

    let old_mappings = old_manifest.get_env(env_name);
    let old_groups: Vec<_> = old_manifest
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .collect();

    let total_ops = old_mappings.len() + old_groups.len() + 1; // +1 for manifest
    let pb = ProgressBar::new(total_ops as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    // ── Re-push standalone files from old state ───────────────────────────────
    for mapping in old_mappings {
        let rel = Path::new(&mapping.local_path);
        let flat = flatten_path(rel);
        let remote = remote_path(&cfg.name, env_name, &flat);

        pb.set_message(mapping.local_path.clone());
        match github.pull_file_at_ref(&remote, &target_sha).await {
            Ok(old_content) => {
                github
                    .push_file(
                        &remote,
                        &old_content,
                        &format!(
                            "latch: rollback {}/{}/{} to {}",
                            cfg.name, env_name, flat, short_sha
                        ),
                    )
                    .await?;
            }
            Err(e) => {
                tracing::warn!(
                    "Could not fetch {} at {}: {} — skipping",
                    remote,
                    short_sha,
                    e
                );
            }
        }
        pb.inc(1);
    }

    // ── Re-push group blobs from old state ────────────────────────────────────
    for group in &old_groups {
        pb.set_message(format!("group:{}", group.name));
        match github
            .pull_file_at_ref(&group.remote_blob, &target_sha)
            .await
        {
            Ok(old_blob) => {
                github
                    .push_file(
                        &group.remote_blob,
                        &old_blob,
                        &format!(
                            "latch: rollback group {}/{}/{} to {}",
                            cfg.name, env_name, group.name, short_sha
                        ),
                    )
                    .await?;
            }
            Err(e) => {
                tracing::warn!(
                    "Could not fetch group blob {} at {}: {} — skipping",
                    group.remote_blob,
                    short_sha,
                    e
                );
            }
        }
        pb.inc(1);
    }

    // ── Merge old env state into current manifest and push ───────────────────
    // Only this env's data is rolled back; other envs stay at current state.
    pb.set_message("updating manifest");
    let current_bytes = github.pull_file(&manifest_path).await?;
    let mut current_manifest = Manifest::from_bytes(&current_bytes)?;

    current_manifest.set_env(env_name, old_manifest.get_env(env_name).to_vec());
    current_manifest.clone_groups.retain(|g| g.env != env_name);
    for g in old_groups {
        current_manifest.clone_groups.push(g.clone());
    }

    github
        .push_file(
            &manifest_path,
            &current_manifest.to_bytes()?,
            &format!("latch: rollback {}/{} to {}", cfg.name, env_name, short_sha),
        )
        .await?;
    pb.inc(1);

    pb.finish_with_message("✓ Rollback complete");
    println!(
        "\nRollback to {} complete. Run 'latch pull --env {}' to restore local files.",
        short_sha, env_name
    );
    Ok(())
}
