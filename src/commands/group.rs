use anyhow::Result;
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::{CloneGroup, Manifest},
};

/// `latch group list [--env <env>]`
pub async fn run_list(env: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _project_root) = ProjectConfig::find_and_load(&cwd)?;
    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github
        .pull_file(&manifest_path)
        .await
        .map_err(|_| anyhow::anyhow!("manifest.json not found. Run 'latch init' first."))?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let groups: Vec<&CloneGroup> = manifest
        .clone_groups
        .iter()
        .filter(|g| g.env == env)
        .collect();

    if groups.is_empty() {
        println!(
            "No clone groups for project '{}' / env '{}'.",
            cfg.name, env
        );
        println!("Tip: add '# latch:group=<name>' as the first line of identical .env files,");
        println!("     then run 'latch push' to register the group.");
        return Ok(());
    }

    println!("Clone groups for project '{}' / env '{}':\n", cfg.name, env);
    for group in &groups {
        let n = group.members.len();
        println!(
            "  {} ({} member{})",
            group.name,
            n,
            if n == 1 { "" } else { "s" }
        );
    }
    println!("\nRun 'latch group show <name>' to see members of a specific group.");
    Ok(())
}

/// `latch group show <name> [--env <env>]`
pub async fn run_show(env: &str, group_name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _project_root) = ProjectConfig::find_and_load(&cwd)?;
    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let manifest_bytes = github
        .pull_file(&manifest_path)
        .await
        .map_err(|_| anyhow::anyhow!("manifest.json not found. Run 'latch init' first."))?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let group = manifest
        .clone_groups
        .iter()
        .find(|g| g.name == group_name && g.env == env)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Clone group '{}' not found for env '{}'. Run 'latch group list' to see available groups.",
                group_name,
                env
            )
        })?;

    println!(
        "Clone group '{}' / env '{}' ({} member{}):\n",
        group.name,
        group.env,
        group.members.len(),
        if group.members.len() == 1 { "" } else { "s" }
    );
    for member in &group.members {
        println!("  {}", member);
    }
    println!("\n  Remote blob: {}", group.remote_blob);
    println!(
        "\nTo add a member: add '# latch:group={}' as the first line of the .env file, then run 'latch push'.",
        group.name
    );
    println!("To remove a member: delete the pragma line, then run 'latch push'.");
    Ok(())
}
