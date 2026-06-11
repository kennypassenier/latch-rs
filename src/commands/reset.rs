use anyhow::Result;
use std::env;

use crate::{
    config::{global::GlobalConfig, latch_home, project::ProjectConfig},
    credentials::{
        GLOBAL_KEY_SLOT, GLOBAL_PAT_SLOT, GLOBAL_SECRETS_REPO_SLOT,
        keyring_provider::KeyringProvider,
    },
};

pub async fn run() -> Result<()> {
    let mut global = GlobalConfig::load()?;

    // Clear global keyring slots.
    let mut keyring_slots: Vec<String> = vec![
        GLOBAL_PAT_SLOT.to_string(),
        GLOBAL_KEY_SLOT.to_string(),
        GLOBAL_SECRETS_REPO_SLOT.to_string(),
    ];

    // Clear known project slots from keyring.
    for p in &global.projects {
        keyring_slots.push(format!("{}.key", p.name));
        keyring_slots.push(format!("{}.pat", p.name));
        keyring_slots.push(format!("{}.key.{}", p.name, p.default_env));
    }

    keyring_slots.sort();
    keyring_slots.dedup();

    let mut keyring_cleared = 0usize;
    for slot in &keyring_slots {
        if KeyringProvider::delete_raw(slot).is_ok() {
            keyring_cleared += 1;
        }
    }

    // Keep project metadata, drop all secret material from global config fallback.
    global.global_pat = None;
    global.global_key_hex = None;
    for p in &mut global.projects {
        p.key_hex = None;
        p.github_pat = None;
    }
    global.save()?;

    // Clear global latch home caches/artifacts but keep global config.toml.
    let home_removed = clear_dir_keep_config(&latch_home())?;

    // If inside a project, clear local .latch cache/staging but keep .latch/config.toml.
    let mut local_removed = 0usize;
    let cwd = env::current_dir()?;
    if let Ok((_cfg, root)) = ProjectConfig::find_and_load(&cwd) {
        local_removed = clear_dir_keep_config(&root.join(".latch"))?;
    }

    println!("Latch reset complete.");
    println!("  keyring slots cleared: {}", keyring_cleared);
    println!("  global cache entries removed: {}", home_removed);
    println!("  local .latch cache entries removed: {}", local_removed);
    println!("  kept project .latch/config.toml and metadata in ~/.latch/config.toml");
    Ok(())
}

fn clear_dir_keep_config(dir: &std::path::Path) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        let keep = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "config.toml")
            .unwrap_or(false);

        if keep {
            continue;
        }

        let ty = entry.file_type()?;
        if ty.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        removed += 1;
    }

    Ok(removed)
}
