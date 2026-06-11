use anyhow::{Result, bail};
use dialoguer::{Input, Password};

use crate::{
    config::global::GlobalConfig,
    credentials::keyring_provider::KeyringProvider,
    credentials::{DEFAULT_SECRETS_REPO, set_global_key, set_global_pat, set_global_secrets_repo},
    crypto::parse_key,
};

pub struct LoginArgs {
    pub pat: Option<String>,
    pub key: Option<String>,
    pub repo: Option<String>,
}

pub async fn run(args: LoginArgs) -> Result<()> {
    println!("Configure global Latch credentials\n");

    let pat: String = match args.pat {
        Some(v) => v,
        None => Password::new()
            .with_prompt("GitHub Personal Access Token (repo scope)")
            .interact()?,
    };
    if pat.trim().is_empty() {
        bail!("PAT cannot be empty");
    }

    let key_input: String = match args.key {
        Some(v) => v,
        None => Password::new()
            .with_prompt("Global encryption key (64 hex or 44 base64 chars)")
            .interact()?,
    };
    if key_input.trim().is_empty() {
        bail!("KEY cannot be empty");
    }
    // Normalize to hex so one canonical value is persisted everywhere.
    let key_hex = hex::encode(parse_key(&key_input)?);

    let repo: String = match args.repo {
        Some(v) => v,
        None => Input::new()
            .with_prompt("Default secrets repo (owner/repo)")
            .default(DEFAULT_SECRETS_REPO.to_string())
            .interact_text()?,
    };
    if !repo.contains('/') {
        bail!("Secrets repo must be in 'owner/repo' format, e.g. acme/secrets");
    }

    let pat_keyring_ok = set_global_pat(&pat).is_ok()
        && KeyringProvider::get_raw("github.pat").as_deref() == Some(pat.as_str());
    let key_keyring_ok = set_global_key(&key_hex).is_ok()
        && KeyringProvider::get_raw("global.key").as_deref() == Some(key_hex.as_str());
    let repo_keyring_ok = set_global_secrets_repo(&repo).is_ok()
        && KeyringProvider::get_raw("github.secrets_repo").as_deref() == Some(repo.as_str());

    // Durable fallback for keyring-less environments (LXC/headless hosts).
    let mut global = GlobalConfig::load()?;
    global.global_pat = Some(pat);
    global.global_key_hex = Some(key_hex);
    global.default_secrets_repo = Some(repo.clone());

    // Keep known project entries aligned with the global key so stale
    // per-project keys cannot silently diverge across machines.
    for project in &mut global.projects {
        project.key_hex = global.global_key_hex.clone();
        let slot = format!("{}.key", project.name);
        let _ = KeyringProvider::set_raw(&slot, project.key_hex.as_deref().unwrap_or_default());
    }

    global.save()?;

    if pat_keyring_ok && key_keyring_ok && repo_keyring_ok {
        println!("Stored PAT, KEY, and default secrets repo in OS keyring.");
    } else {
        println!(
            "OS keyring unavailable for one or more values; credentials were saved to ~/.latch/config.toml fallback."
        );
    }
    println!("Defaults configured: secrets repo = {}", repo);
    println!("You can now run 'latch init' in new folders without entering them again.");
    Ok(())
}
