use super::*;
use crate::config::global;
use anyhow::{Context, Result, bail};
use octocrab::Octocrab;
use std::io::{Seek, SeekFrom, Write};

/// Fetches the contents of a file from a Git repository
pub async fn get_contents(repo_name: &str, branch: &str, path: &str) -> Result<String> {
    let client = Octocrab::instance().context("Failed to create GitHub client")?;

    // Use octocrab's get_contents which returns a Vec<RepoContent>
    let response: Result<Vec<_>, _> = client
        .repos
        .get_contents(repo_name, path, Some(branch))
        .await;

    match response {
        Ok(items) => {
            if let Some(item) = items.first() {
                match item {
                    octocrab::models::RepoContent::File(file) => {
                        let content_str = String::from_utf8(file.content.clone())
                            .context("Failed to decode file content as UTF-8")?;
                        Ok(content_str)
                    }
                    octocrab::models::RepoContent::Dir(_) => {
                        anyhow::bail!("Path is a directory, not a file")
                    }
                }
            } else {
                anyhow::bail!("File '{}' not found", path)
            }
        }
        Err(e) => Err(e).context("Failed to fetch file contents from GitHub"),
    }
}

/// Writes the contents of a file to a Git repository using octocrab's create_or_update_file
pub async fn write_contents(
    repo_name: &str,
    branch: &str,
    path: &str,
    content: &str,
) -> Result<()> {
    let client = Octocrab::instance().context("Failed to create GitHub client")?;

    // First, get the current SHA of the file for the update
    let response: Result<Vec<_>, _> = client
        .repos
        .get_contents(repo_name, path, Some(branch))
        .await;

    match response {
        Ok(items) => {
            if let Some(item) = items.first() {
                match item {
                    octocrab::models::RepoContent::File(file) => {
                        // Create the tree item for update
                        let tree_item = octocrab::models::CreateOrUpdateFileRequest {
                            path: path.to_string(),
                            message: Some("Update secrets".to_string()),
                            content: Some(base64_encode(content)),
                            sha: file.sha.clone(), // Required for updates
                            branch: None,
                        };

                        client
                            .repos
                            .create_or_update_file(repo_name, tree_item)
                            .await
                            .context("Failed to update file in repository")?;

                        Ok(())
                    }
                    octocrab::models::RepoContent::Dir(_) => {
                        anyhow::bail!("Path is a directory, not a file")
                    }
                }
            } else {
                // File doesn't exist, so create it (SHA can be empty for new files)
                let tree_item = octocrab::models::CreateOrUpdateFileRequest {
                    path: path.to_string(),
                    message: Some("Create secrets".to_string()),
                    content: Some(base64_encode(content)),
                    sha: None, // New file
                    branch: None,
                };

                client
                    .repos
                    .create_or_update_file(repo_name, tree_item)
                    .await
                    .context("Failed to create file in repository")?;

                Ok(())
            }
        }
        Err(e) => {
            anyhow::bail!("Error fetching file for update: {}", e)
        }
    }
}

/// Base64 encode a string (octocrab expects base64 encoded content for API calls)
fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}
