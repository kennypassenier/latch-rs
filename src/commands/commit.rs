use anyhow::Result;
use dialoguer::Select;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, encrypt, parse_key},
    discovery::{
        flatten_path, generate_example, has_key_value_pairs, local_blob_path,
        local_group_blob_path, scan_env_files, write_example,
    },
    manifest::{CloneGroup, FileMapping, Manifest},
};

// ── Clone-group helpers ───────────────────────────────────────────────────────

/// Encrypt a clone group and write it to the local `.latch/` staging area.
///
/// Subscribe-intent members (pragma present, no KEY=VALUE pairs) are resolved
/// against the local cache instead of GitHub — so `commit` works offline
/// after an initial `latch pull`.
async fn process_group(
    group_name: &str,
    members: &[PathBuf],
    project_root: &Path,
    env_name: &str,
    key: &[u8; 32],
    pb: &ProgressBar,
) -> Result<Option<CloneGroup>> {
    let local_blob = local_group_blob_path(project_root, env_name, group_name);

    let mut content_members: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for abs in members {
        if has_key_value_pairs(abs) {
            content_members.push((abs.clone(), std::fs::read(abs)?));
        }
    }

    // Subscribe intent: all members only have pragma/comments/blank lines.
    let canonical_bytes: Vec<u8> = if content_members.is_empty() {
        if local_blob.exists() {
            // Decrypt the cached blob to recover the canonical plaintext.
            let ciphertext = std::fs::read(&local_blob)?;
            decrypt(&ciphertext, key)?
        } else {
            // No local cache after reset means we cannot recover subscribe-only
            // group content. Error out — silently skipping would leave a stale,
            // possibly wrong-key blob in the remote.
            anyhow::bail!(
                "Clone group '{}' has subscribe-only members and no local cache.\n\
                 Run 'latch pull --env {}' first to populate the cache, then retry commit.",
                group_name,
                env_name
            );
        }
    } else if content_members.len() == 1 {
        content_members[0].1.clone()
    } else {
        let first = &content_members[0].1;
        if content_members[1..].iter().all(|(_, b)| b == first) {
            first.clone()
        } else {
            pb.suspend(|| {
                println!(
                    "  ⚠ Clone group '{}' diverged across {} member files:",
                    group_name,
                    content_members.len()
                );
                for (abs, _) in &content_members {
                    let rel = abs.strip_prefix(project_root).unwrap_or(abs);
                    println!("      {}", rel.display());
                }
            });

            let labels: Vec<String> = content_members
                .iter()
                .map(|(abs, _)| {
                    abs.strip_prefix(project_root)
                        .unwrap_or(abs)
                        .display()
                        .to_string()
                })
                .collect();

            let idx = pb.suspend(|| {
                Select::new()
                    .with_prompt("Pick the source of truth for this group")
                    .items(&labels)
                    .default(0)
                    .interact()
            })?;
            content_members[idx].1.clone()
        }
    };

    // Sync canonical content back to all member files + examples.
    for abs in members {
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(abs, &canonical_bytes)?;
        let example = generate_example(&String::from_utf8_lossy(&canonical_bytes));
        write_example(abs, &example)?;
    }

    // Encrypt and write to local staging area.
    let ciphertext = encrypt(&canonical_bytes, key)?;
    if let Some(parent) = local_blob.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&local_blob, &ciphertext)?;

    // Self-verify: decrypt the blob we just wrote and confirm it matches.
    let verify_ct = std::fs::read(&local_blob)?;
    let verify_pt = decrypt(&verify_ct, key).map_err(|_| {
        anyhow::anyhow!(
            "BUG: group blob for '{}' cannot be decrypted with the key we just used. \
             Key fp:{}",
            group_name,
            key_fingerprint(key)
        )
    })?;
    if verify_pt != canonical_bytes {
        anyhow::bail!(
            "BUG: group blob '{}' round-trip content mismatch.",
            group_name
        );
    }

    pb.set_message(format!("group:{}", group_name));

    let member_paths = members
        .iter()
        .map(|a| {
            a.strip_prefix(project_root)
                .unwrap_or(a)
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    Ok(Some(CloneGroup {
        name: group_name.to_string(),
        env: env_name.to_string(),
        remote_blob: CloneGroup::remote_blob_path(
            // We don't have the project name here; it will be filled in by run().
            // Use a placeholder that run() replaces.
            "__project__",
            env_name,
            group_name,
        ),
        members: member_paths,
    }))
}

// ── Main command ──────────────────────────────────────────────────────────────

fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("fp:{}", hex::encode(&digest[..6]))
}

pub async fn run(env_name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env_name))?;
    let key = parse_key(&key_hex)?;
    println!(
        "Using key ({}) for project '{}' env '{}'",
        key_fingerprint(&key),
        cfg.name,
        env_name
    );

    // Load any existing staging manifest so we can preserve other envs.
    let mut staging =
        Manifest::load_staging(&project_root)?.unwrap_or_else(|| Manifest::new(&cfg.name, None));

    let all_files = scan_env_files(&project_root);
    if all_files.is_empty() {
        // Clear this env from staging if it was previously tracked.
        staging.set_env(env_name, Vec::new());
        staging.clone_groups.retain(|g| g.env != env_name);
        staging.save_staging(&project_root)?;
        println!(
            "No .env files found in {}. Cleared staged files for env '{}'.",
            project_root.display(),
            env_name
        );
        return Ok(());
    }

    let raw_groups: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut standalone_paths: Vec<PathBuf> = Vec::new();

    for abs_path in &all_files {
        // TEMPORARY: clone groups are disabled; stage every .env as standalone.
        standalone_paths.push(abs_path.clone());
    }

    let total_ops = standalone_paths.len() + raw_groups.len();
    println!(
        "Found {} .env file(s) ({} standalone, groups disabled) - encrypting to .latch/ (env: {})",
        all_files.len(),
        standalone_paths.len(),
        env_name
    );

    let pb = ProgressBar::new(total_ops as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    let mut new_groups: Vec<CloneGroup> = Vec::new();
    for (group_name, members) in &raw_groups {
        if let Some(mut group) =
            process_group(group_name, members, &project_root, env_name, &key, &pb).await?
        {
            // Fix up the remote_blob path with the real project name.
            group.remote_blob = CloneGroup::remote_blob_path(&cfg.name, env_name, group_name);
            new_groups.push(group);
        }
        pb.inc(1);
    }

    let mut new_mappings: Vec<FileMapping> = Vec::new();
    for abs_path in &standalone_paths {
        let rel_path = abs_path
            .strip_prefix(&project_root)
            .unwrap_or(abs_path.as_path());
        let flat = flatten_path(rel_path);

        pb.set_message(format!("{}", rel_path.display()));

        let content = std::fs::read(abs_path)?;
        let example = generate_example(&String::from_utf8_lossy(&content));
        write_example(abs_path, &example)?;

        let ciphertext = encrypt(&content, &key)?;
        let local_blob = local_blob_path(&project_root, env_name, &flat);
        if let Some(parent) = local_blob.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&local_blob, &ciphertext)?;

        // Self-verify: blob must be decryptable with the key we just used.
        let verify_ct = std::fs::read(&local_blob)?;
        decrypt(&verify_ct, &key).map_err(|_| {
            anyhow::anyhow!(
                "BUG: blob for '{}' cannot be decrypted after writing. Key fp:{}",
                rel_path.display(),
                key_fingerprint(&key)
            )
        })?;

        new_mappings.push(FileMapping {
            local_path: rel_path.to_string_lossy().into_owned(),
        });
        pb.inc(1);
    }

    pb.finish_with_message("All files staged");

    // Update the staging manifest for this env; preserve other envs.
    staging.project = cfg.name.clone();
    staging.set_env(env_name, new_mappings);
    staging.clone_groups.retain(|g| g.env != env_name);
    staging.clone_groups.extend(new_groups);

    staging.save_staging(&project_root)?;

    let total_staged = staging.get_env(env_name).len()
        + staging
            .clone_groups
            .iter()
            .filter(|g| g.env == env_name)
            .count();

    println!(
        "\nStaged {} file(s) for env '{}' in .latch/. All blobs verified OK.",
        total_staged, env_name
    );
    println!("Run 'latch push --env {}' to upload to GitHub.", env_name);
    Ok(())
}
