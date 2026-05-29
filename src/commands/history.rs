use anyhow::Result;
use std::env;

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    github::{RemoteStorageExt as _, client::GitHubClient},
    manifest::Manifest,
};

/// `latch history [--env <env>] [--limit <n>]`
///
/// Lists the most recent save operations for the current project by reading
/// GitHub commit history for the manifest file.
pub async fn run(env: &str, limit: usize) -> Result<()> {
    let cwd = env::current_dir()?;
    let (cfg, _project_root) = ProjectConfig::find_and_load(&cwd)?;
    let chain = FallbackChain::new(&cfg.name);
    let pat = chain.get_pat()?;
    let github = GitHubClient::new(&cfg.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&cfg.name);
    let commits = github.list_commits(&manifest_path, limit).await?;

    if commits.is_empty() {
        println!(
            "No history found for project '{}'. Run 'latch push' first.",
            cfg.name
        );
        return Ok(());
    }

    println!(
        "Save history for project '{}' (env hint: '{}'):\n",
        cfg.name, env
    );
    println!("  {:<8}  {:<10}  {:<24}  Message", "#", "SHA", "Date");
    println!(
        "  {}  {}  {}  {}",
        "─".repeat(8),
        "─".repeat(10),
        "─".repeat(24),
        "─".repeat(50)
    );

    for (i, commit) in commits.iter().enumerate() {
        let short_sha = &commit.sha[..commit.sha.len().min(8)];
        let date_short = commit.date.get(..19).unwrap_or(&commit.date);
        let first_line = commit.message.lines().next().unwrap_or("(no message)");
        let marker = if i == 0 { " ← current" } else { "" };
        println!(
            "  {:<8}  {:<10}  {:<24}  {}{}",
            format!("#{}", i + 1),
            short_sha,
            date_short,
            first_line,
            marker
        );
    }

    println!(
        "\nTo roll back: latch rollback --env {} --steps <n>  or  latch rollback --to <sha>",
        env
    );
    Ok(())
}
