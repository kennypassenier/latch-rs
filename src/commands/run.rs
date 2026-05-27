use anyhow::Result;
use std::{env, process::Command};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{expand_env_vars, flatten_path, remote_path},
    github::{client::GitHubClient, RemoteStorage as _},
    manifest::Manifest,
};

/// `latch run [--env <env>] -- <program> [args…]`
///
/// Fetches and decrypts secrets for `env`, injects them into the child
/// process's environment, then execs the child.  The plaintext never
/// touches the filesystem.  Template references (`${VAR}`, `$VAR`) in
/// values are expanded before injection (feature 8.4).
pub async fn run(env_name: &str, program: &str, args: &[String]) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, project_root) = ProjectConfig::find_and_load(&cwd)?;

    let chain = FallbackChain::new(&cfg.name);
    let key_hex = chain.get_key_for_env(Some(env_name))?;
    let key = parse_key(&key_hex)?;
    let pat = chain.get_pat()?;

    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github.pull_file(&manifest_path).await.map_err(|_| {
        anyhow::anyhow!("manifest.json not found. Run 'latch init' first.")
    })?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env_name);
    if mappings.is_empty() {
        anyhow::bail!(
            "No files tracked for env '{}'. Run 'latch save --env {}' first.",
            env_name,
            env_name
        );
    }

    // Collect all key=value pairs across every .env file for this env,
    // accumulating resolved pairs so later lines can reference earlier ones.
    let mut resolved: Vec<(String, String)> = Vec::new();

    for mapping in mappings {
        let rel_path = std::path::Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&cfg.name, env_name, &flat);

        let ciphertext = github.pull_file(&remote).await?;
        let plaintext = decrypt(&ciphertext, &key)?;
        let content = String::from_utf8_lossy(&plaintext);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            if let Some(eq) = line.find('=') {
                let k = line[..eq].trim().to_string();
                let raw_v = line[eq + 1..].to_string();
                let expanded = expand_env_vars(&raw_v, &resolved);
                if !k.is_empty() {
                    resolved.push((k, expanded));
                }
            }
        }
    }

    tracing::debug!("Injecting {} env var(s) for env '{}'", resolved.len(), env_name);

    let _ = project_root; // only needed for context
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.envs(resolved.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    let status = cmd.status()?;
    let code = status.code().unwrap_or(1);
    if code != 0 { std::process::exit(code); }
    Ok(())
}
