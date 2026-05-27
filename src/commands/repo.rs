use anyhow::{Context, Result};
use std::fs;

/// Initialize a new git repository for the secrets of a project
pub struct RepoInitResult {
    pub path: String,
}

/// Initialize a git repository at the given path
pub async fn init_git_repository(path: &str, project: &str) -> Result<RepoInitResult> {
    // Create directory if it doesn't exist
    fs::create_dir_all(path).context(format!("Failed to create directory: {}", path))?;

    // Initialize git repository
    let output = std::process::Command::new("git")
        .args(["init"])
        .arg(path)
        .output()
        .context("Failed to execute git init")?;

    if !output.status.success() {
        anyhow::bail!(
            "Git initialization failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Create initial empty .gitkeep file
    fs::write(format!("{}/.gitkeep", path), "").context("Failed to create .gitkeep")?;

    // Set up git config for secrets repo (no hooks, clean history)
    let _ = std::process::Command::new("git")
        .args(["config", "user.email", "secrets@local"])
        .arg(path)
        .output();

    let _ = std::process::Command::new("git")
        .args(["config", "user.name", "Secrets Bot"])
        .arg(path)
        .output();

    // Configure git to skip GPG signing for local ops
    let _ = std::process::Command::new("git")
        .args(["config", "--local", "commit.gpgsign", "false"])
        .arg(path)
        .output();

    Ok(RepoInitResult {
        path: path.to_string(),
    })
}

/// Clone or update the secrets repository from GitHub
pub async fn clone_secrets_repo(token: &str, repo_url: &str) -> Result<()> {
    // Ensure git is available
    which::which("git")?;

    let output = std::process::Command::new("git")
        .args(["clone", "--bare", "--depth=1"])
        .arg(repo_url)
        .output()
        .context("Failed to clone secrets repository")?;

    if !output.status.success() {
        anyhow::bail!("Clone failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    println!("✓ Cloned secrets repository");
    Ok(())
}

/// Get the secrets repository URL for a project
pub fn get_secrets_repo_url(token: &str, project: &str) -> Result<String> {
    let config_path = crate::config::home_dir().join("config.toml");

    if !config_path.exists() {
        anyhow::bail!("Config not found. Run 'latch init' first.");
    }

    let content = fs::read_to_string(&config_path)?;
    let doc: toml_edit::Document = content.parse()?;

    // Check global section for project-specific repo URL
    if let Some(global_item) = doc.get("global").and_then(|it| it.as_value()) {
        if let Some(repo_url) = global_item.get(project) {
            return Ok(repo_url.as_str().unwrap_or("").to_string());
        }
    }

    // Default: assume standard naming convention
    // In a real implementation, this would parse from config or env var
    anyhow::bail!(
        "Repository URL not found for project '{}'. Run 'latch setproject' to configure.",
        project
    )
}

/// Resolve the secrets repository path
pub fn secrets_repo_path() -> String {
    let home = crate::config::home_dir();
    format!("{}/.secrets", home.display())
}

/// Commit changes in the secrets repo with a message
pub fn commit_with_message(repo_path: &str, message: &str) -> Result<()> {
    let status_output = std::process::Command::new("git")
        .args(["-C", repo_path, "status"])
        .output()
        .context("Failed to execute git status")?;

    if !status_output.status.success() {
        anyhow::bail!(
            "Git status failed: {}",
            String::from_utf8_lossy(&status_output.stderr)
        );
    }

    // Check for uncommitted changes
    let stdout = String::from_utf8_lossy(&status_output.stdout);

    if stdout.contains("nothing to commit") || stdout.contains("(no changes since...)") {
        return Ok(());
    }

    // Add all changes
    std::process::Command::new("git")
        .args(["-C", repo_path, "add", "."])
        .output()
        .context("Failed to execute git add")?;

    if !status_output.status.success() {
        anyhow::bail!(
            "Git add failed: {}",
            String::from_utf8_lossy(&status_output.stderr)
        );
    }

    // Commit with message
    let output = std::process::Command::new("git")
        .args(["-C", repo_path, "commit", "-m"])
        .arg(message)
        .output()
        .context("Failed to execute git commit")?;

    if !output.status.success() {
        anyhow::bail!(
            "Git commit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}
