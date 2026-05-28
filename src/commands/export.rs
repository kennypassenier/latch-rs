use anyhow::Result;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use std::{env, path::Path};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run(env: &str, dry_run: bool) -> Result<()> {
    // ── Load config ───────────────────────────────────────────────────────────
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    // ── Load credentials ──────────────────────────────────────────────────────
    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env))?;
    let key = parse_key(&key_hex)?;
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // ── Fetch manifest ────────────────────────────────────────────────────────
    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github.pull_file(&manifest_path).await.map_err(|_| {
        anyhow::anyhow!(
            "manifest.json not found in {}. Run 'latch init' first.",
            cfg.secrets_repo
        )
    })?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env);
    if mappings.is_empty() {
        println!(
            "No files tracked for env '{}' in project '{}'. Run 'latch save --env {}' first.",
            env, cfg.name, env
        );
        return Ok(());
    }

    if dry_run {
        println!(
            "[dry-run] Would export {} file(s) for env '{}' into {}",
            mappings.len(),
            env,
            project_root.display()
        );
        for m in mappings {
            let rel = &m.local_path;
            let flat = flatten_path(Path::new(rel));
            let remote = remote_path(&cfg.name, env, &flat);
            println!("  {} ← {}", rel, remote);
        }
        return Ok(());
    }

    println!(
        "Exporting {} file(s) for env '{}' from {} → {}",
        mappings.len(),
        env,
        cfg.secrets_repo,
        project_root.display()
    );

    // ── Progress bar ──────────────────────────────────────────────────────────
    let pb = ProgressBar::new(mappings.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    let mut written = 0usize;
    let mut skipped = 0usize;

    for mapping in mappings {
        let rel_path = Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env, &flat);
        let local_abs = project_root.join(rel_path);

        pb.set_message(format!("{}", rel_path.display()));
        tracing::debug!("Pulling {} → {}", remote, local_abs.display());

        // Fetch and decrypt
        let ciphertext = github.pull_file(&remote).await?;
        let plaintext = decrypt(&ciphertext, &key)?;

        // ── Overwrite protection ──────────────────────────────────────────────
        if local_abs.exists() {
            let existing = std::fs::read(&local_abs)?;
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
                        tracing::info!("Skipped {}", rel_path.display());
                        skipped += 1;
                        pb.inc(1);
                        continue;
                    }
                }
            }
        }

        // Create parent directories and write
        if let Some(parent) = local_abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&local_abs, &plaintext)?;
        tracing::debug!("Wrote {}", local_abs.display());
        written += 1;
        pb.inc(1);
    }

    pb.finish_with_message("✓ Export complete");
    println!("\nExported {} file(s), skipped {}.", written, skipped);
    Ok(())
}
