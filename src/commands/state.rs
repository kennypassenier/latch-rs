use anyhow::Result;
use sha2::{Digest, Sha256};
use std::env;

use crate::{
    config::{global::GlobalConfig, project::ProjectConfig},
    credentials::{
        FallbackChain, GLOBAL_KEY_SLOT, GLOBAL_PAT_SLOT, GLOBAL_SECRETS_REPO_SLOT,
        keyring_provider::KeyringProvider,
    },
    crypto::parse_key,
};

pub async fn run(env_name: &str, pull_command: bool, reveal: bool, sparse: bool) -> Result<()> {
    let cwd = env::current_dir()?;

    println!("Latch state");
    println!("  cwd: {}", cwd.display());

    match ProjectConfig::find_and_load(&cwd) {
        Ok((cfg, root)) => {
            println!(
                "  project config: {}",
                root.join(".latch/config.toml").display()
            );
            println!("  project name: {}", cfg.name);
            println!("  project repo: {}", cfg.secrets_repo);
            println!("  project default env: {}", cfg.default_env);
        }
        Err(_) => {
            println!("  project config: not found from cwd upward");
        }
    }

    println!("\nEnvironment variables");
    print_key_source("env:LATCH_KEY", std::env::var("LATCH_KEY").ok().as_deref());
    print_pat_source("env:LATCH_PAT", std::env::var("LATCH_PAT").ok().as_deref());

    let global = GlobalConfig::load()?;
    println!("\nGlobal config (~/.latch/config.toml)");
    println!(
        "  default_secrets_repo: {}",
        global.default_secrets_repo.as_deref().unwrap_or("<none>")
    );
    print_key_source("config:global_key_hex", global.global_key_hex.as_deref());
    print_pat_source("config:global_pat", global.global_pat.as_deref());

    println!("  projects: {}", global.projects.len());
    for p in &global.projects {
        println!(
            "  - {} (repo={}, default_env={})",
            p.name, p.secrets_repo, p.default_env
        );
        print_key_source("    key_hex", p.key_hex.as_deref());
        print_pat_source("    github_pat", p.github_pat.as_deref());
    }

    println!("\nKeyring slots (known)");
    print_key_source(
        &format!("keyring:{}", GLOBAL_KEY_SLOT),
        KeyringProvider::get_raw(GLOBAL_KEY_SLOT).as_deref(),
    );
    print_pat_source(
        &format!("keyring:{}", GLOBAL_PAT_SLOT),
        KeyringProvider::get_raw(GLOBAL_PAT_SLOT).as_deref(),
    );
    print_repo_source(
        &format!("keyring:{}", GLOBAL_SECRETS_REPO_SLOT),
        KeyringProvider::get_raw(GLOBAL_SECRETS_REPO_SLOT).as_deref(),
    );

    for p in &global.projects {
        let pkey = format!("{}.key", p.name);
        let ppat = format!("{}.pat", p.name);
        let ekey = format!("{}.key.{}", p.name, env_name);

        print_key_source(
            &format!("keyring:{}", pkey),
            KeyringProvider::get_raw(&pkey).as_deref(),
        );
        print_key_source(
            &format!("keyring:{}", ekey),
            KeyringProvider::get_raw(&ekey).as_deref(),
        );
        print_pat_source(
            &format!("keyring:{}", ppat),
            KeyringProvider::get_raw(&ppat).as_deref(),
        );
    }

    if pull_command {
        println!("\nOne-shot pull command");
        let (cfg, _root) = ProjectConfig::find_and_load(&cwd).map_err(|_| {
            anyhow::anyhow!(
                "No .latch/config.toml found from cwd upward. Run this command from a project folder initialized with Latch."
            )
        })?;

        let chain = FallbackChain::new(&cfg.name);
        let pat = chain.get_pat()?;
        let key = chain.get_key_for_env(Some(env_name))?;

        let shown_pat = if reveal {
            pat
        } else {
            format!("<redacted:{}>", mask_compact(&pat))
        };
        let shown_key = if reveal {
            key
        } else {
            format!("<redacted:{}>", mask_compact(&key))
        };

        println!("latch pull \\");
        println!("  --env {} \\", shell_quote(env_name));
        if sparse {
            println!("  --sparse \\");
        }
        println!("  --PAT {} \\", shell_quote(&shown_pat));
        println!("  --KEY {} \\", shell_quote(&shown_key));
        println!("  --REPO {} \\", shell_quote(&cfg.secrets_repo));
        println!("  --project {}", shell_quote(&cfg.name));

        if !reveal {
            println!(
                "\nUse --reveal to print raw PAT/KEY values (sensitive; avoid shell history leaks)."
            );
        }
    }

    Ok(())
}

fn print_key_source(label: &str, value: Option<&str>) {
    match value {
        Some(v) => {
            let parsed = parse_key(v);
            match parsed {
                Ok(key) => {
                    println!(
                        "  {}: present ({}, len={})",
                        label,
                        key_fingerprint(&key),
                        v.len()
                    );
                }
                Err(_) => {
                    println!("  {}: present (invalid key format, len={})", label, v.len());
                }
            }
        }
        None => println!("  {}: <none>", label),
    }
}

fn print_pat_source(label: &str, value: Option<&str>) {
    match value {
        Some(v) => println!("  {}: present ({})", label, mask(v)),
        None => println!("  {}: <none>", label),
    }
}

fn print_repo_source(label: &str, value: Option<&str>) {
    match value {
        Some(v) => println!("  {}: {}", label, v),
        None => println!("  {}: <none>", label),
    }
}

fn mask(s: &str) -> String {
    if s.len() <= 8 {
        return "****".to_string();
    }
    format!("{}...{} (len={})", &s[..4], &s[s.len() - 4..], s.len())
}

fn mask_compact(s: &str) -> String {
    if s.len() <= 8 {
        return "****".to_string();
    }
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("fp:{}", hex::encode(&digest[..6]))
}
