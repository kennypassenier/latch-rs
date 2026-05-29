use anyhow::Result;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use std::{env, path::Path};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, local_blob_path, local_group_blob_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run(env_name: &str, dry_run: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env_name))?;
    let key = parse_key(&key_hex)?;
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
        println!(
            "[dry-run] Would pull {} standalone file(s) + {} group(s) for env '{}' into {}",
            mappings.len(),
            groups.len(),
            env_name,
            project_root.display()
        );
        for m in mappings {
            let rel = &m.local_path;
            let flat = flatten_path(Path::new(rel));
            let remote = remote_path(&cfg.name, env_name, &flat);
            println!("  {} <- {}", rel, remote);
        }
        for g in &groups {
            println!(
                "  group '{}' ({} member(s)) <- {}",
                g.name,
                g.members.len(),
                g.remote_blob
            );
        }
        return Ok(());
    }

    let total = mappings.len() + groups.iter().map(|g| g.members.len()).sum::<usize>();
    println!(
        "Pulling {} file(s) for env '{}' from {} -> {}",
        total,
        env_name,
        cfg.secrets_repo,
        project_root.display()
    );

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

        let ciphertext = github.pull_file(&remote).await?;
        // Cache encrypted blob to .latch/ for offline commit and subscribe-intent.
        let cached = local_blob_path(&project_root, env_name, &flat);
        if let Some(p) = cached.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cached, &ciphertext)?;
        let plaintext = decrypt(&ciphertext, &key)?;
        write_file!(&local_abs, &plaintext);
    }

    for group in &groups {
        pb.set_message(format!("group:{}", group.name));
        let ciphertext = github.pull_file(&group.remote_blob).await?;
        // Cache group blob to .latch/ so subscribe-intent members can commit offline.
        let cached = local_group_blob_path(&project_root, env_name, &group.name);
        if let Some(p) = cached.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cached, &ciphertext)?;
        let plaintext = decrypt(&ciphertext, &key)?;

        for member_path in &group.members {
            let local_abs = project_root.join(member_path);
            pb.set_message(member_path.clone());
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
