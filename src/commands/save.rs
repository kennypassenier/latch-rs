use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{encrypt, parse_key},
    discovery::{flatten_path, generate_example, remote_path, scan_env_files, write_example},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::{FileMapping, Manifest},
};

pub async fn run(env: &str) -> Result<()> {
    // ── Load config ───────────────────────────────────────────────────────────
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;
    tracing::debug!("Project root: {}", project_root.display());

    // ── Load credentials ──────────────────────────────────────────────────────
    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env))?;
    let key = parse_key(&key_hex)?;
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // ── Fetch / create manifest ───────────────────────────────────────────────
    let manifest_path = Manifest::remote_path(&cfg.name);
    let mut manifest = match github.get_sha(&manifest_path).await? {
        Some(_) => {
            let bytes = github.pull_file(&manifest_path).await?;
            Manifest::from_bytes(&bytes)?
        }
        None => Manifest::new(&cfg.name, None),
    };
    let previous_mappings = manifest.get_env(env).to_vec();

    // ── Discover .env files ───────────────────────────────────────────────────
    let all_files = scan_env_files(&project_root);
    if all_files.is_empty() {
        if !previous_mappings.is_empty() {
            for mapping in &previous_mappings {
                let rel = std::path::Path::new(&mapping.local_path);
                let flat = flatten_path(rel);
                let remote = remote_path(&cfg.name, env, &flat);
                github
                    .delete_file(
                        &remote,
                        &format!("latch: remove stale {}/{}/{}", cfg.name, env, flat),
                    )
                    .await?;
            }

            manifest.set_env(env, Vec::new());
            let manifest_bytes = manifest.to_bytes()?;
            github
                .push_file(
                    &manifest_path,
                    &manifest_bytes,
                    &format!("latch: prune manifest for {}/{}", cfg.name, env),
                )
                .await?;
            println!(
                "No .env files found in {}. Cleared tracked files for env '{}' from the manifest.",
                project_root.display(),
                env
            );
        } else {
            println!(
                "No .env files found in {}. Nothing to do.",
                project_root.display()
            );
        }
        return Ok(());
    }
    println!(
        "Found {} .env file(s) – encrypting and pushing to {} (env: {})",
        all_files.len(),
        cfg.secrets_repo,
        env
    );

    // ── Progress bar ──────────────────────────────────────────────────────────
    let pb = ProgressBar::new(all_files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    let mut new_mappings: Vec<FileMapping> = Vec::new();

    for abs_path in &all_files {
        let rel_path = abs_path
            .strip_prefix(&project_root)
            .unwrap_or(abs_path.as_path());
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env, &flat);

        pb.set_message(format!("{}", rel_path.display()));
        tracing::debug!("Processing {} → {}", rel_path.display(), remote);

        // Read plaintext .env
        let content = std::fs::read(abs_path)?;

        // Generate .env.example alongside the source file
        let example = generate_example(&String::from_utf8_lossy(&content));
        write_example(abs_path, &example)?;

        // Encrypt
        let ciphertext = encrypt(&content, &key)?;

        // Push to GitHub
        let commit_msg = format!("latch: update {}/{}/{}", cfg.name, env, flat);
        github.push_file(&remote, &ciphertext, &commit_msg).await?;
        tracing::debug!("Pushed {}", remote);

        new_mappings.push(FileMapping {
            local_path: rel_path.to_string_lossy().into_owned(),
        });

        pb.inc(1);
    }

    pb.finish_with_message("✓ All files uploaded");

    // Remove remote files that used to be tracked but are no longer discovered
    // (for example after adding entries to .latchignore).
    let new_paths: HashSet<&str> = new_mappings.iter().map(|m| m.local_path.as_str()).collect();
    for old in previous_mappings {
        if new_paths.contains(old.local_path.as_str()) {
            continue;
        }
        let rel = std::path::Path::new(&old.local_path);
        let flat = flatten_path(rel);
        let remote = remote_path(&cfg.name, env, &flat);
        github
            .delete_file(
                &remote,
                &format!("latch: remove stale {}/{}/{}", cfg.name, env, flat),
            )
            .await?;
    }

    // ── Update manifest ───────────────────────────────────────────────────────
    manifest.set_env(env, new_mappings);
    let manifest_bytes = manifest.to_bytes()?;
    github
        .push_file(
            &manifest_path,
            &manifest_bytes,
            &format!("latch: update manifest for {}/{}", cfg.name, env),
        )
        .await?;
    println!("✓ Manifest updated.");

    println!(
        "\nAll done! Export on another machine with: latch export --env {}",
        env
    );
    Ok(())
}
