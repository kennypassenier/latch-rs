use anyhow::{Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "windows")]
use anyhow::bail;

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(any(not(target_os = "windows"), test))]
const PATH_BLOCK_START: &str = "# >>> latch path >>>";
#[cfg(any(not(target_os = "windows"), test))]
const PATH_BLOCK_END: &str = "# <<< latch path <<<";

pub async fn add() -> Result<()> {
    let current = env::current_exe().context("Cannot determine current executable path")?;
    let target = install_target()?;

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Creating {}", parent.display()))?;
    }

    copy_executable(&current, &target)?;
    configure_user_path_add(target.parent().expect("install target has parent"))?;

    println!("Installed Latch to {}", target.display());
    println!("Open a new shell, or reload your shell profile, before running 'latch'.");
    Ok(())
}

pub async fn remove() -> Result<()> {
    let target = install_target()?;
    let install_dir = target.parent().expect("install target has parent");

    if target.exists() {
        fs::remove_file(&target).with_context(|| format!("Removing {}", target.display()))?;
        println!("Removed {}", target.display());
    } else {
        println!("No installed Latch binary found at {}", target.display());
    }

    configure_user_path_remove(install_dir)?;
    println!("Open a new shell, or reload your shell profile, for PATH changes to take effect.");
    Ok(())
}

pub async fn status() -> Result<()> {
    let current = env::current_exe().context("Cannot determine current executable path")?;
    let target = install_target()?;
    let install_dir = target.parent().expect("install target has parent");

    println!("Current executable: {}", current.display());
    println!("Managed install path: {}", target.display());
    println!(
        "Managed binary exists: {}",
        if target.exists() { "yes" } else { "no" }
    );
    println!(
        "PATH contains install directory: {}",
        if path_contains(install_dir) {
            "yes"
        } else {
            "no"
        }
    );

    #[cfg(not(target_os = "windows"))]
    for profile in unix_profile_files() {
        if profile.exists() {
            let text = fs::read_to_string(&profile).unwrap_or_default();
            println!(
                "Managed PATH block in {}: {}",
                profile.display(),
                if text.contains(PATH_BLOCK_START) {
                    "yes"
                } else {
                    "no"
                }
            );
        }
    }

    Ok(())
}

pub(crate) fn install_target() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let dir = dirs::data_local_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine LOCALAPPDATA directory"))?
            .join("Programs")
            .join("latch");
        return Ok(dir.join("latch.exe"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".local")
            .join("bin");
        Ok(dir.join("latch"))
    }
}

pub(crate) fn copy_executable(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to)
        .with_context(|| format!("Copying {} -> {}", from.display(), to.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(to)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(to, perms)?;
    }

    Ok(())
}

fn path_contains(dir: &Path) -> bool {
    env::split_paths(&env::var_os("PATH").unwrap_or_default()).any(|p| p == dir)
}

pub(crate) fn configure_user_path_add(install_dir: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_update_user_path(install_dir, true)?;
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        if path_contains(install_dir) {
            println!("{} is already on PATH.", install_dir.display());
            return Ok(());
        }

        let block = format!(
            "{}\nexport PATH=\"$HOME/.local/bin:$PATH\"\n{}",
            PATH_BLOCK_START, PATH_BLOCK_END
        );

        for profile in unix_profile_files() {
            upsert_managed_block_in_file(&profile, &block)?;
        }
        Ok(())
    }
}

fn configure_user_path_remove(install_dir: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_update_user_path(install_dir, false)?;
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = install_dir;
        for profile in unix_profile_files() {
            remove_managed_block_from_file(&profile)?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn unix_profile_files() -> Vec<PathBuf> {
    let home = dirs::home_dir().expect("home directory available");
    vec![
        home.join(".profile"),
        home.join(".bashrc"),
        home.join(".zshrc"),
    ]
}

#[cfg(not(target_os = "windows"))]
fn upsert_managed_block_in_file(path: &Path, block: &str) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let updated = upsert_managed_block(&existing, block);
    fs::write(path, updated).with_context(|| format!("Writing {}", path.display()))?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn remove_managed_block_from_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let existing = fs::read_to_string(path).unwrap_or_default();
    let updated = remove_managed_block(&existing);
    fs::write(path, updated).with_context(|| format!("Writing {}", path.display()))?;
    Ok(())
}

#[cfg(any(not(target_os = "windows"), test))]
fn upsert_managed_block(existing: &str, block: &str) -> String {
    let trimmed = remove_managed_block(existing).trim_end().to_string();
    if trimmed.is_empty() {
        format!("{}\n", block)
    } else {
        format!("{}\n\n{}\n", trimmed, block)
    }
}

#[cfg(any(not(target_os = "windows"), test))]
fn remove_managed_block(existing: &str) -> String {
    if let Some(start) = existing.find(PATH_BLOCK_START) {
        if let Some(rel_end) = existing[start..].find(PATH_BLOCK_END) {
            let end = start + rel_end + PATH_BLOCK_END.len();
            let before = existing[..start].trim_end();
            let after = existing[end..].trim_start_matches(['\r', '\n']);
            return match (before.is_empty(), after.is_empty()) {
                (true, true) => String::new(),
                (true, false) => format!("{}\n", after.trim_end()),
                (false, true) => format!("{}\n", before),
                (false, false) => format!("{}\n\n{}\n", before, after.trim_end()),
            };
        }
    }
    existing.to_string()
}

#[cfg(target_os = "windows")]
fn windows_update_user_path(install_dir: &Path, add: bool) -> Result<()> {
    let install_dir = install_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Install directory contains invalid Unicode"))?;
    let escaped = install_dir.replace('"', "`\"");
    let script = if add {
        format!(
            "$dir = \"{}\"; \
             $current = [Environment]::GetEnvironmentVariable('Path', 'User'); \
             $parts = @(); \
             if ($current) {{ $parts = $current -split ';' | Where-Object {{ $_ -ne '' }} }}; \
             if (-not ($parts -contains $dir)) {{ $parts += $dir; [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User') }}",
            escaped
        )
    } else {
        format!(
            "$dir = \"{}\"; \
             $current = [Environment]::GetEnvironmentVariable('Path', 'User'); \
             $parts = @(); \
             if ($current) {{ $parts = $current -split ';' | Where-Object {{ $_ -and $_ -ne $dir }} }}; \
             [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')",
            escaped
        )
    };

    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("Running PowerShell to update user PATH")?;

    if !status.success() {
        bail!("PowerShell failed while updating the user PATH");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PATH_BLOCK_END, PATH_BLOCK_START, remove_managed_block, upsert_managed_block};

    #[test]
    fn upsert_adds_single_managed_block() {
        let block = format!("{}\nexport PATH=foo\n{}", PATH_BLOCK_START, PATH_BLOCK_END);
        let initial = "export EDITOR=vim\n";
        let once = upsert_managed_block(initial, &block);
        let twice = upsert_managed_block(&once, &block);

        assert_eq!(once, twice);
        assert_eq!(once.matches(PATH_BLOCK_START).count(), 1);
    }

    #[test]
    fn remove_drops_managed_block_cleanly() {
        let text = format!(
            "export EDITOR=vim\n\n{}\nexport PATH=foo\n{}\n",
            PATH_BLOCK_START, PATH_BLOCK_END
        );
        assert_eq!(remove_managed_block(&text), "export EDITOR=vim\n");
    }
}
