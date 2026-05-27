use anyhow::Result;
use dialoguer::{Input, Password, Select};
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::{keyring_provider::KeyringProvider, FallbackChain},
    crypto::{generate_key_hex, parse_key, kdf::{decode_salt, derive_key, generate_salt_b64}},
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
    println!("Setting encryption key for project '{}' / {}\n", cfg.name, scope);

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
            println!("\n  KDF salt (share this with team members): {}\n", salt_b64);
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
            KeyringProvider::set_raw(&format!("{}.key", cfg.name), &key_hex)?;
            println!("  Default project key saved to OS keyring.");
        }
    }

    println!("\nDone. Run 'latch save --env <env>' to re-encrypt secrets with the new key.");
    Ok(())
}
