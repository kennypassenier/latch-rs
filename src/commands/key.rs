use anyhow::Result;
use dialoguer::{Input, Password, Select};
use std::env;

use crate::{
    config::{
        global::{GlobalConfig, ProjectEntry},
        project::ProjectConfig,
    },
    credentials::{FallbackChain, keyring_provider::KeyringProvider},
    crypto::{
        generate_key_hex,
        kdf::{decode_salt, derive_key, generate_salt_b64},
        parse_key,
    },
};

/// `latch key [--env <env>]`
///
/// Set or rotate the encryption key for a specific environment.
/// Leaves all other envs' keys untouched (8.5 multi-key support).
pub async fn run(env_name: Option<&str>) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _root) = ProjectConfig::find_and_load(&cwd)?;

    let scope = match env_name {
        Some(e) => format!("env '{}'", e),
        None => "project default (all envs)".to_string(),
    };
    println!(
        "Setting encryption key for project '{}' / {}\n",
        cfg.name, scope
    );

    let choices = &[
        "Generate random key (recommended)",
        "Derive from passphrase (Argon2id)",
        "Paste existing key (hex or base64)",
    ];
    let mode = Select::new()
        .with_prompt("Key source")
        .items(choices)
        .default(0)
        .interact()?;

    let key_hex = match mode {
        0 => {
            let hex = generate_key_hex();
            println!("\n  New key (store this safely!):\n  {}\n", hex);
            hex
        }
        1 => {
            let passphrase: String = Password::new()
                .with_prompt("Passphrase")
                .with_confirmation("Confirm passphrase", "Passphrases do not match")
                .interact()?;
            let salt_b64 = generate_salt_b64();
            let salt = decode_salt(&salt_b64)?;
            let key = derive_key(&passphrase, &salt)?;
            let hex = hex::encode(key);
            println!(
                "\n  KDF salt (share this with team members): {}\n",
                salt_b64
            );
            println!("  Derived key (stored in keyring):\n  {}\n", hex);
            hex
        }
        2 => {
            let raw: String = Input::new()
                .with_prompt("Key (64 hex chars or 44 base64 chars)")
                .interact_text()?;
            parse_key(&raw)?; // validate length
            raw
        }
        _ => unreachable!(),
    };

    match env_name {
        Some(env) => {
            FallbackChain::new(&cfg.name).set_key_for_env(env, &key_hex)?;
            println!("  Key for env '{}' saved to OS keyring.", env);
            println!("  Slot: '{}.key.{}'", cfg.name, env);
        }
        None => {
            let slot = format!("{}.key", cfg.name);
            let keyring_round_trip_ok = match KeyringProvider::set_raw(&slot, &key_hex) {
                Ok(()) => KeyringProvider::get_raw(&slot).as_deref() == Some(key_hex.as_str()),
                Err(_) => false,
            };

            if keyring_round_trip_ok {
                println!("  Default project key saved to OS keyring.");
            } else {
                let mut global = GlobalConfig::load()?;
                let existing = global
                    .get_project(&cfg.name)
                    .cloned()
                    .unwrap_or(ProjectEntry {
                        name: cfg.name.clone(),
                        secrets_repo: cfg.secrets_repo.clone(),
                        default_env: cfg.default_env.clone(),
                        key_hex: None,
                        github_pat: None,
                    });
                global.upsert_project(ProjectEntry {
                    key_hex: Some(key_hex.clone()),
                    ..existing
                });
                global.save()?;
                println!(
                    "  OS keyring is unavailable or unreadable in this session; saved the default project key to ~/.latch/config.toml instead."
                );
            }
        }
    }

    println!("\nDone. Run 'latch push --env <env>' to re-encrypt secrets with the new key.");
    Ok(())
}
