use anyhow::{Result, bail};
use dialoguer::{Confirm, Input, Select};
use std::collections::BTreeSet;
use std::env;

use crate::config::{
    global::{GlobalConfig, ProjectEntry},
    project::ProjectConfig,
};
use crate::credentials::{
    CredentialProvider, FallbackChain, get_global_pat, get_global_secrets_repo,
    keyring_provider::KeyringProvider,
};
use crate::github::{RemoteStorage as _, client::GitHubClient};
use crate::manifest::Manifest;

fn resolve_repo_from_global(global: &GlobalConfig) -> Option<String> {
    if let Some(repo) = get_global_secrets_repo() {
        return Some(repo);
    }

    let repos = global
        .projects
        .iter()
        .map(|p| p.secrets_repo.clone())
        .collect::<BTreeSet<_>>();

    if repos.len() == 1 {
        repos.iter().next().cloned()
    } else {
        None
    }
}

fn resolve_pat(global: &GlobalConfig) -> Result<String> {
    if let Some(v) = get_global_pat() {
        return Ok(v);
    }

    if let Ok(v) = env::var("LATCH_PAT") {
        if !v.trim().is_empty() {
            return Ok(v);
        }
    }

    for p in &global.projects {
        if let Ok(pat) = FallbackChain::new(&p.name).get_pat() {
            return Ok(pat);
        }
    }

    let entered: String = Input::new()
        .with_prompt("GitHub Personal Access Token (repo scope)")
        .interact_text()?;
    if entered.trim().is_empty() {
        bail!("No PAT available. Set LATCH_PAT or run 'latch init' in an existing project first.");
    }
    Ok(entered)
}

async fn list_remote_projects(client: &GitHubClient) -> Result<Vec<String>> {
    let files = client.list_files("").await?;
    let mut names = BTreeSet::new();

    for path in files {
        if let Some(prefix) = path.strip_suffix("/manifest.json") {
            if !prefix.is_empty() && !prefix.contains('/') {
                names.insert(prefix.to_string());
            }
        }
    }

    Ok(names.into_iter().collect())
}

fn choose_repo(global: &GlobalConfig, explicit_repo: Option<&str>) -> Result<String> {
    if let Some(r) = explicit_repo {
        return Ok(r.to_string());
    }

    if let Some(r) = resolve_repo_from_global(global) {
        return Ok(r);
    }

    bail!("No default secrets repo configured. Run 'latch login' first, or pass --repo owner/repo.")
}

pub async fn list(repo: Option<&str>) -> Result<()> {
    let global = GlobalConfig::load().unwrap_or_default();
    let selected_repo = choose_repo(&global, repo)?;
    let pat = resolve_pat(&global)?;

    let github = GitHubClient::new(&selected_repo, &pat)?;
    let projects = list_remote_projects(&github).await?;

    if projects.is_empty() {
        println!(
            "No projects found in {} (no */manifest.json files).",
            selected_repo
        );
        return Ok(());
    }

    println!("Projects in {}:", selected_repo);
    for p in projects {
        println!("  - {}", p);
    }

    Ok(())
}

pub async fn use_in_current_dir(repo: Option<&str>, env_override: Option<&str>) -> Result<()> {
    let cwd = env::current_dir()?;
    let global = GlobalConfig::load().unwrap_or_default();
    let selected_repo = choose_repo(&global, repo)?;
    let pat = resolve_pat(&global)?;

    let github = GitHubClient::new(&selected_repo, &pat)?;
    let projects = list_remote_projects(&github).await?;
    if projects.is_empty() {
        bail!("No projects found in {}.", selected_repo);
    }

    let project_idx = Select::new()
        .with_prompt("Choose project to bind to this folder")
        .items(&projects)
        .default(0)
        .interact()?;
    let project_name = projects[project_idx].clone();

    let manifest_path = Manifest::remote_path(&project_name);
    let manifest_bytes = github.pull_file(&manifest_path).await?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let envs = manifest
        .envs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let selected_env = if let Some(env) = env_override {
        env.to_string()
    } else if envs.is_empty() {
        "dev".to_string()
    } else {
        let default_idx = envs.iter().position(|e| e == "dev").unwrap_or(0);
        let idx = Select::new()
            .with_prompt("Choose default environment")
            .items(&envs)
            .default(default_idx)
            .interact()?;
        envs[idx].clone()
    };

    let target_cfg = ProjectConfig {
        name: project_name.clone(),
        secrets_repo: selected_repo.clone(),
        default_env: selected_env.clone(),
    };

    let cfg_path = cwd.join(".latch").join("config.toml");
    if cfg_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} exists. Overwrite with selected project config?",
                cfg_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            println!("Cancelled. Existing project config left unchanged.");
            return Ok(());
        }
    }

    target_cfg.save_in(&cwd)?;

    // Best-effort: if PAT is not yet in keyring for this project, store it.
    let keyring = KeyringProvider;
    if keyring.get_pat(&project_name).is_none() {
        let _ = keyring.set_credentials(&project_name, Some(&pat), None);
    }

    let existing = global
        .get_project(&project_name)
        .cloned()
        .unwrap_or(ProjectEntry {
            name: project_name.clone(),
            secrets_repo: selected_repo.clone(),
            default_env: selected_env.clone(),
            key_hex: None,
            github_pat: None,
        });

    let mut updated = global;
    updated.upsert_project(ProjectEntry {
        name: project_name.clone(),
        secrets_repo: selected_repo.clone(),
        default_env: selected_env.clone(),
        key_hex: existing.key_hex,
        github_pat: existing.github_pat,
    });
    let _ = updated.save();

    println!(
        "Bound current folder to project '{}' (repo: {}, env: {}).",
        project_name, selected_repo, selected_env
    );

    let do_export = Confirm::new()
        .with_prompt("Run load now?")
        .default(true)
        .interact()?;
    if do_export {
        crate::commands::export::run(&selected_env, false).await?;
    }

    Ok(())
}

pub async fn run(repo: Option<&str>, env_override: Option<&str>) -> Result<()> {
    use_in_current_dir(repo, env_override).await
}
