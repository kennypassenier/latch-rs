use anyhow::Result;
use dialoguer::{Confirm, Password};
use indicatif::{ProgressBar, ProgressStyle};
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::{CredentialProvider, FallbackChain, keyring_provider::KeyringProvider},
    crypto::{decrypt, encrypt, generate_key_hex, parse_key},
    discovery::{flatten_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run() -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _project_root) = ProjectConfig::find_and_load(&cwd)?;

    // ── Load current credentials ──────────────────────────────────────────────
    let chain = FallbackChain::new(&cfg.name);
    let old_key_hex = chain.get_key_for_env(None)?;
    let old_key = parse_key(&old_key_hex)?;
    let pat = chain.get_pat()?;

    println!("Rotating encryption key for project '{}'", cfg.name);
    println!("This will re-encrypt ALL secrets with a new key.\n");

    if !Confirm::new()
        .with_prompt("Continue?")
        .default(false)
        .interact()?
    {
        println!("Aborted.");
        return Ok(());
    }

    // ── New key ───────────────────────────────────────────────────────────────
    let new_key_choices = &[
        "Generate random key (recommended)",
        "Enter new key manually",
    ];
    let choice = dialoguer::Select::new()
        .with_prompt("New key source")
        .items(new_key_choices)
        .default(0)
        .interact()?;

    let new_key_hex = if choice == 0 {
        generate_key_hex()
    } else {
        let raw: String = Password::new()
            .with_prompt("New key (64 hex chars or 44 base64 chars)")
            .interact()?;
        parse_key(&raw)?; // validate
        raw
    };
    let new_key = parse_key(&new_key_hex)?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    // ── Fetch manifest ────────────────────────────────────────────────────────
    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github
        .pull_file(&manifest_path)
        .await
        .map_err(|_| anyhow::anyhow!("manifest.json not found. Run 'latch init' first."))?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    // Collect every encrypted file across all envs
    let mut all_remote_paths: Vec<String> = Vec::new();
    for (env_name, mappings) in &manifest.envs {
        for mapping in mappings {
            let flat = flatten_path(std::path::Path::new(&mapping.local_path));
            all_remote_paths.push(remote_path(&cfg.name, env_name, &flat));
        }
    }

    if all_remote_paths.is_empty() {
        println!("No encrypted files found in manifest. Nothing to rotate.");
        return Ok(());
    }

    println!("\nRe-encrypting {} file(s)…", all_remote_paths.len());

    let pb = ProgressBar::new(all_remote_paths.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    for remote in &all_remote_paths {
        pb.set_message(remote.clone());

        // Pull → decrypt with old key → encrypt with new key → push
        let ciphertext = github.pull_file(remote).await?;
        let plaintext = decrypt(&ciphertext, &old_key)?;
        let new_ciphertext = encrypt(&plaintext, &new_key)?;
        github
            .push_file(
                remote,
                &new_ciphertext,
                &format!("latch: rotate key for {}", remote),
            )
            .await?;

        pb.inc(1);
    }
    pb.finish_with_message("✓ All files re-encrypted");

    // ── Persist new key ───────────────────────────────────────────────────────
    let keyring = KeyringProvider;
    keyring.set_credentials(&cfg.name, None, Some(&new_key_hex))?;
    println!("\n  New key saved to OS keyring.");
    println!("\n  New key (store this safely!):\n  {}\n", new_key_hex);
    println!(
        "⚠  All team members must update their local keyring with the new key\n   \
           before running 'latch load'."
    );

    Ok(())
}
