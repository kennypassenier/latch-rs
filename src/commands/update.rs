use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Deserialize;
use std::fs;

use crate::commands::path::{configure_user_path_add, install_target};

const BUILD_VERSION: &str = match option_env!("LATCH_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

pub async fn run() -> Result<()> {
    let (owner, repo) = parse_repository(REPOSITORY_URL)?;
    let asset_names = target_asset_names()?;

    let client = Client::builder()
        .user_agent(format!("latch-rs/{}", BUILD_VERSION))
        .build()
        .context("Building HTTP client")?;

    let release = fetch_latest_release(&client, &owner, &repo).await?;
    let asset = asset_names
        .iter()
        .find_map(|name| release.assets.iter().find(|asset| asset.name == **name))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Latest release {} does not contain any supported assets: {}.",
                release.tag_name,
                asset_names.join(", ")
            )
        })?;

    let binary = download_and_extract_binary(&client, &asset.browser_download_url).await?;

    let target = install_target()?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creating install directory {}", parent.display()))?;
    }

    let tmp_target = target.with_extension("new");
    fs::write(&tmp_target, binary)
        .with_context(|| format!("Writing downloaded binary to {}", tmp_target.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(&tmp_target)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_target, perms)?;
    }

    fs::rename(&tmp_target, &target)
        .with_context(|| format!("Installing updated binary to {}", target.display()))?;

    configure_user_path_add(target.parent().expect("install target has parent"))?;

    println!("Updated Latch to {}.", release.tag_name);
    println!("Executable name remains: latch");
    println!("Installed binary: {}", target.display());
    println!("Open a new shell if PATH changes do not apply immediately.");

    Ok(())
}

async fn fetch_latest_release(client: &Client, owner: &str, repo: &str) -> Result<Release> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        owner, repo
    );

    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("Fetching latest release metadata")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("GitHub release lookup failed with {}: {}", status, body);
    }

    resp.json::<Release>()
        .await
        .context("Parsing latest release metadata")
}

async fn download_and_extract_binary(client: &Client, asset_url: &str) -> Result<Vec<u8>> {
    let resp = client
        .get(asset_url)
        .send()
        .await
        .context("Downloading release archive")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Release download failed with {}: {}", status, body);
    }

    let archive_bytes = resp.bytes().await.context("Reading release archive body")?;

    let gz = flate2::read::GzDecoder::new(&archive_bytes[..]);
    let mut archive = tar::Archive::new(gz);

    for entry in archive
        .entries()
        .context("Reading release archive entries")?
    {
        let mut entry = entry.context("Reading release archive entry")?;
        let path = entry.path().context("Reading entry path")?;
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "latch")
        {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf)
                .context("Extracting binary from release archive")?;
            return Ok(buf);
        }
    }

    bail!("Release archive does not contain a 'latch' binary");
}

fn parse_repository(url: &str) -> Result<(String, String)> {
    let trimmed = url.trim_end_matches('/');
    let without_git = trimmed.trim_end_matches(".git");
    let (owner, repo) = without_git
        .rsplit_once('/')
        .ok_or_else(|| anyhow::anyhow!("Invalid repository URL: {}", url))?;

    let owner = owner
        .rsplit_once('/')
        .map(|(_, value)| value)
        .unwrap_or(owner);

    if owner.is_empty() || repo.is_empty() {
        bail!("Invalid repository URL: {}", url);
    }

    Ok((owner.to_string(), repo.to_string()))
}

fn target_asset_names() -> Result<Vec<&'static str>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Prefer the Debian 12 / glibc 2.36-compatible build. It runs on both
        // older LXC environments and newer host systems.
        Ok(vec![
            "latch-linux-x86_64-lxc.tar.gz",
            "latch-linux-x86_64.tar.gz",
        ])
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        bail!(
            "'latch update' is currently supported only on Linux x86_64. Use the GitHub Releases page for your platform."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::parse_repository;

    #[test]
    fn parse_repository_supports_https_and_git_suffix() {
        let (owner, repo) = parse_repository("https://github.com/kennypassenier/latch-rs.git")
            .expect("parse repo url");
        assert_eq!(owner, "kennypassenier");
        assert_eq!(repo, "latch-rs");
    }
}
