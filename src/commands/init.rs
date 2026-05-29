use anyhow::{Result, bail};
use dialoguer::{Input, Password, Select};
use std::env;

use crate::{
    config::{
        global::{GlobalConfig, ProjectEntry},
        project::ProjectConfig,
    },
    credentials::{
        CredentialProvider, get_global_pat, get_global_secrets_repo,
        keyring_provider::KeyringProvider,
    },
    crypto::{
        generate_key_hex,
        kdf::{decode_salt, derive_key, generate_salt_b64},
        parse_key,
    },
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

pub async fn run() -> Result<()> {
    println!("Initialising Latch for this project\n");
    let keyring = KeyringProvider;

    // ── Project name ──────────────────────────────────────────────────────────
    let default_name = env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "myproject".to_string());

    let project_name: String = Input::new()
        .with_prompt("Project name")
        .default(default_name)
        .interact_text()?;

    // ── Secrets repo ──────────────────────────────────────────────────────────
    let secrets_repo = match get_global_secrets_repo() {
        Some(repo) => {
            println!("  Using secrets repo from keyring: {}", repo);
            repo
        }
        None => {
            bail!(
                "No default secrets repo found in keyring. Run 'latch login' first (it stores PAT + owner/repo)."
            )
        }
    };

    if !secrets_repo.contains('/') {
        bail!("Secrets repo must be in 'owner/repo' format, e.g. acme/latch-secrets");
    }

    // ── Default environment ───────────────────────────────────────────────────
    let default_env: String = Input::new()
        .with_prompt("Default environment")
        .default("dev".to_string())
        .interact_text()?;

    // ── GitHub PAT ────────────────────────────────────────────────────────────
    let pat = match get_global_pat() {
        Some(v) => {
            println!("  Using GitHub PAT from keyring.");
            v
        }
        None => {
            bail!("No GitHub PAT found in keyring. Run 'latch login' first.")
        }
    };

    // ── Encryption key ────────────────────────────────────────────────────────
    let existing_key = keyring.get_key(&project_name);
    let (key_hex, kdf_salt_b64) = if let Some(existing) = existing_key {
        println!("  Reusing existing project key from keyring.");
        (existing, None)
    } else {
        let key_choices = &[
            "Generate random key (recommended)",
            "Derive from passphrase",
            "Paste existing key (hex or base64)",
        ];
        let key_mode = Select::new()
            .with_prompt("Encryption key setup")
            .items(key_choices)
            .default(0)
            .interact()?;

        match key_mode {
            0 => {
                // Generate random key
                let hex = generate_key_hex();
                println!("\n  Generated key (save this somewhere safe!)\n  {}\n", hex);
                (hex, None)
            }
            1 => {
                // Passphrase mode – derive key + store salt in manifest
                let passphrase: String = Password::new()
                    .with_prompt("Passphrase")
                    .with_confirmation("Confirm passphrase", "Passphrases do not match")
                    .interact()?;
                let salt_b64 = generate_salt_b64();
                let salt = decode_salt(&salt_b64)?;
                let key = derive_key(&passphrase, &salt)?;
                let hex = hex::encode(key);
                println!("\n  KDF salt (stored in manifest): {}\n", salt_b64);
                (hex, Some(salt_b64))
            }
            2 => {
                // Accept pasted key
                let raw: String = Input::new()
                    .with_prompt("Key (64 hex chars or 44 base64 chars)")
                    .interact_text()?;
                // Validate key by parsing it
                parse_key(&raw)?;
                (raw, None)
            }
            _ => unreachable!(),
        }
    };

    // ── Persist credentials ──────────────────────────────────────────────────
    let keyring_round_trip_ok =
        match keyring.set_credentials(&project_name, Some(&pat), Some(&key_hex)) {
            Ok(()) => {
                let pat_ok = keyring.get_pat(&project_name).as_deref() == Some(pat.as_str());
                let key_ok = keyring.get_key(&project_name).as_deref() == Some(key_hex.as_str());
                pat_ok && key_ok
            }
            Err(_) => false,
        };

    if keyring_round_trip_ok {
        println!("  Credentials saved to OS keyring.");
    } else {
        println!(
            "  OS keyring is unavailable or unreadable in this session; storing fallback credentials in ~/.latch/config.toml."
        );
    }

    // ── Write .latch/config.toml in CWD ──────────────────────────────────────
    let cwd = env::current_dir()?;
    let project_cfg = ProjectConfig {
        name: project_name.clone(),
        secrets_repo: secrets_repo.clone(),
        default_env: default_env.clone(),
    };
    project_cfg.save_in(&cwd)?;
    println!("  Wrote .latch/config.toml");

    // ── Update ~/.latch/config.toml (fallback) ────────────────────────────────
    let mut global = GlobalConfig::load()?;
    global.upsert_project(ProjectEntry {
        name: project_name.clone(),
        secrets_repo: secrets_repo.clone(),
        default_env: default_env.clone(),
        key_hex: (!keyring_round_trip_ok).then_some(key_hex.clone()),
        github_pat: (!keyring_round_trip_ok).then_some(pat.clone()),
    });
    global.save()?;
    println!("  Updated ~/.latch/config.toml");

    // ── Bootstrap manifest in GitHub repo if absent ───────────────────────────
    let client = GitHubClient::new(&secrets_repo, &pat)?;
    let manifest_path = Manifest::remote_path(&project_name);

    match client.get_sha(&manifest_path).await? {
        Some(_) => {
            println!("  Manifest already exists in remote – skipping creation.");
        }
        None => {
            let manifest = Manifest::new(&project_name, kdf_salt_b64);
            let bytes = manifest.to_bytes()?;
            client
                .push_file(
                    &manifest_path,
                    &bytes,
                    &format!("latch: init manifest for {}", project_name),
                )
                .await?;
            println!("  Created manifest.json in remote repo.");
        }
    }

    println!(
        "\nLatch initialised!  Run 'latch push --env {}' to encrypt and push your .env files.",
        default_env
    );
    Ok(())
}
