use anyhow::Result;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::{env, path::Path};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, local_blob_path, local_group_blob_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run(env_name: &str, dry_run: bool, sparse: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github.pull_file(&manifest_path).await.map_err(|_| {
        anyhow::anyhow!(
            "manifest.json not found in {}. Run 'latch init' first.",
            cfg.secrets_repo
        )
    })?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env_name);
    let groups: Vec<_> = manifest
        .clone_groups
        .iter()
        .filter(|g| g.env == env_name)
        .collect();

    if mappings.is_empty() && groups.is_empty() {
        println!(
            "No files tracked for env '{}' in project '{}'. Run 'latch push --env {}' first.",
            env_name, cfg.name, env_name
        );
        return Ok(());
    }

    if dry_run {
        let mode = if sparse { "sparse" } else { "full" };
        println!(
            "[dry-run][{}] Would pull {} standalone file(s) + {} group(s) for env '{}' into {}",
            mode,
            mappings.len(),
            groups.len(),
            env_name,
            project_root.display()
        );
        for m in mappings {
            let rel = &m.local_path;
            let flat = flatten_path(Path::new(rel));
            let remote = remote_path(&cfg.name, env_name, &flat);
            let local_abs = project_root.join(rel);
            if should_skip_for_sparse(&local_abs, sparse) {
                println!("  {} <- {} [skip: parent directory missing]", rel, remote);
            } else {
                println!("  {} <- {}", rel, remote);
            }
        }
        for g in &groups {
            println!(
                "  group '{}' ({} member(s)) <- {}",
                g.name,
                g.members.len(),
                g.remote_blob
            );
            if sparse {
                for member in &g.members {
                    let local_abs = project_root.join(member);
                    if should_skip_for_sparse(&local_abs, true) {
                        println!("    - {} [skip: parent directory missing]", member);
                    }
                }
            }
        }
        return Ok(());
    }

    let total = mappings.len() + groups.iter().map(|g| g.members.len()).sum::<usize>();

    // Resolve the effective decryption key by probing known candidates against the
    // first available ciphertext. This prevents stale-source precedence issues.
    let mut first_probe_target: Option<String> = None;
    let mut first_probe_ciphertext: Option<Vec<u8>> = None;
    if let Some(first) = mappings.first() {
        let flat = flatten_path(Path::new(&first.local_path));
        let remote = remote_path(&cfg.name, env_name, &flat);
        first_probe_ciphertext = Some(github.pull_file(&remote).await?);
        first_probe_target = Some(remote);
    } else if let Some(first_group) = groups.first() {
        first_probe_ciphertext = Some(github.pull_file(&first_group.remote_blob).await?);
        first_probe_target = Some(first_group.remote_blob.clone());
    }

    let candidates = chain.key_candidates_for_env(Some(env_name));
    if candidates.is_empty() {
        anyhow::bail!(
            "No encryption key found for env '{}' in project '{}'.",
            env_name,
            cfg.name
        );
    }

    let probe_blob = first_probe_ciphertext
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No ciphertext available to validate decryption key."))?;

    let mut parsed_candidates: Vec<(String, [u8; 32])> = Vec::new();
    let mut chosen_key: Option<[u8; 32]> = None;
    let mut chosen_source: Option<String> = None;
    let mut attempted: Vec<String> = Vec::new();

    for (source, candidate_raw) in candidates {
        let parsed = match parse_key(&candidate_raw) {
            Ok(k) => k,
            Err(_) => {
                attempted.push(format!("{} (invalid-format)", source));
                continue;
            }
        };

        parsed_candidates.push((source.clone(), parsed));

        if decrypt(probe_blob, &parsed).is_ok() {
            chosen_key = Some(parsed);
            chosen_source = Some(source.clone());
            break;
        }

        attempted.push(format!("{} ({})", source, key_fingerprint(&parsed)));
    }

    let key = chosen_key.ok_or_else(|| {
        anyhow::anyhow!(
            "Decryption failed for all known keys while validating '{}'. Tried: {}",
            first_probe_target
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string()),
            attempted.join(", ")
        )
    })?;

    let key_source = chosen_source.unwrap_or_else(|| "unknown".to_string());
    let key_fp = key_fingerprint(&key);
    println!("Using decryption key from {} ({})", key_source, key_fp);

    println!(
        "Pulling {} file(s) for env '{}' from {} -> {}",
        total,
        env_name,
        cfg.secrets_repo,
        project_root.display()
    );
    if sparse {
        println!("Sparse mode enabled: only existing directories will receive .env files.");
    }

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    let mut written = 0usize;
    let mut skipped = 0usize;

    macro_rules! write_file {
        ($local_abs:expr, $plaintext:expr) => {{
            let local_abs: &std::path::Path = $local_abs;
            let plaintext: &[u8] = $plaintext;
            let mut do_write = true;
            if local_abs.exists() {
                let existing = std::fs::read(local_abs)?;
                if existing != plaintext {
                    pb.suspend(|| {
                        println!(
                            "\n  {} already exists and differs from the remote version.",
                            local_abs.display()
                        );
                    });
                    let overwrite = pb.suspend(|| {
                        Confirm::new()
                            .with_prompt(format!("  Overwrite {}?", local_abs.display()))
                            .default(false)
                            .interact()
                    });
                    match overwrite {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            do_write = false;
                        }
                    }
                }
            }
            if do_write {
                if let Some(parent) = local_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(local_abs, plaintext)?;
                written += 1;
            } else {
                skipped += 1;
            }
            pb.inc(1);
        }};
    }

    for mapping in mappings {
        let rel_path = Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env_name, &flat);
        let local_abs = project_root.join(rel_path);

        pb.set_message(format!("{}", rel_path.display()));

        let ciphertext = if first_probe_target.as_deref() == Some(remote.as_str()) {
            first_probe_ciphertext.clone().unwrap_or_default()
        } else {
            github.pull_file(&remote).await?
        };
        // Cache encrypted blob to .latch/ for offline commit and subscribe-intent.
        let cached = local_blob_path(&project_root, env_name, &flat);
        if let Some(p) = cached.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cached, &ciphertext)?;
        let plaintext =
            decrypt_with_candidates(&ciphertext, &remote, &key, &key_source, &parsed_candidates)?;
        if should_skip_for_sparse(&local_abs, sparse) {
            pb.suspend(|| {
                println!(
                    "  skipping {} (parent directory missing)",
                    local_abs.display()
                );
            });
            skipped += 1;
            pb.inc(1);
            continue;
        }
        write_file!(&local_abs, &plaintext);
    }

    for group in &groups {
        pb.set_message(format!("group:{}", group.name));
        let ciphertext = if first_probe_target.as_deref() == Some(group.remote_blob.as_str()) {
            first_probe_ciphertext.clone().unwrap_or_default()
        } else {
            github.pull_file(&group.remote_blob).await?
        };
        // Cache group blob to .latch/ so subscribe-intent members can commit offline.
        let cached = local_group_blob_path(&project_root, env_name, &group.name);
        if let Some(p) = cached.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cached, &ciphertext)?;
        let plaintext = decrypt_with_candidates(
            &ciphertext,
            &group.remote_blob,
            &key,
            &key_source,
            &parsed_candidates,
        )?;

        for member_path in &group.members {
            let local_abs = project_root.join(member_path);
            pb.set_message(member_path.clone());
            if should_skip_for_sparse(&local_abs, sparse) {
                pb.suspend(|| {
                    println!(
                        "  skipping {} (parent directory missing)",
                        local_abs.display()
                    );
                });
                skipped += 1;
                pb.inc(1);
                continue;
            }
            write_file!(&local_abs, &plaintext);
        }
    }

    pb.finish_with_message("Pull complete");
    println!("\nPulled {} file(s), skipped {}.", written, skipped);

    // Update the local staging cache so `latch commit` can work offline
    // and subscribe-intent clone-group members can resolve from the cache.
    manifest.save_staging(&project_root)?;
    Ok(())
}

fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("fp:{}", hex::encode(&digest[..6]))
}

fn decrypt_with_candidates(
    ciphertext: &[u8],
    remote_path: &str,
    primary_key: &[u8; 32],
    primary_source: &str,
    candidates: &[(String, [u8; 32])],
) -> Result<Vec<u8>> {
    if let Ok(plaintext) = decrypt(ciphertext, primary_key) {
        return Ok(plaintext);
    }

    for (source, key) in candidates {
        if source == primary_source {
            continue;
        }
        if let Ok(plaintext) = decrypt(ciphertext, key) {
            return Ok(plaintext);
        }
    }

    let tried = std::iter::once(format!(
        "{} ({})",
        primary_source,
        key_fingerprint(primary_key)
    ))
    .chain(
        candidates
            .iter()
            .filter(|(source, _)| source != primary_source)
            .map(|(source, key)| format!("{} ({})", source, key_fingerprint(key))),
    )
    .collect::<Vec<_>>()
    .join(", ");

    anyhow::bail!(
        "Failed to decrypt remote blob '{}' with all known keys. Tried: {}",
        remote_path,
        tried
    )
}

fn should_skip_for_sparse(local_abs: &Path, sparse: bool) -> bool {
    if !sparse {
        return false;
    }

    match local_abs.parent() {
        Some(parent) => !parent.exists(),
        None => false,
    }
}
