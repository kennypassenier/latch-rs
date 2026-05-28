use anyhow::{Result, bail};
use dialoguer::{Input, Password};

use crate::credentials::{set_global_pat, set_global_secrets_repo};

pub async fn run() -> Result<()> {
    println!("Configure global Latch credentials\n");

    let pat: String = Password::new()
        .with_prompt("GitHub Personal Access Token (repo scope)")
        .interact()?;
    if pat.trim().is_empty() {
        bail!("PAT cannot be empty");
    }

    let repo: String = Input::new()
        .with_prompt("Default secrets repo (owner/repo)")
        .interact_text()?;
    if !repo.contains('/') {
        bail!("Secrets repo must be in 'owner/repo' format, e.g. acme/secrets");
    }

    set_global_pat(&pat)?;
    set_global_secrets_repo(&repo)?;

    println!("Stored PAT and default secrets repo in OS keyring.");
    println!("You can now run 'latch init' in new folders without entering them again.");
    Ok(())
}
