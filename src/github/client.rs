use super::{CommitSummary, RemoteStorage, RemoteStorageExt};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::debug;

const API_BASE: &str = "https://api.github.com";
const ACCEPT_HEADER: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "2022-11-28";
const BUILD_VERSION: &str = match option_env!("LATCH_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ContentsResponse {
    sha: String,
    /// Base64-encoded file content (GitHub inserts newlines every 60 chars).
    content: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TreeItem {
    path: String,
    #[serde(rename = "type")]
    kind: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TreeResponse {
    tree: Vec<TreeItem>,
}

#[derive(Deserialize)]
struct CommitItem {
    sha: String,
    commit: CommitDetail,
}

#[derive(Deserialize)]
struct CommitDetail {
    message: String,
    author: CommitAuthorInfo,
}

#[derive(Deserialize)]
struct CommitAuthorInfo {
    name: String,
    #[allow(dead_code)]
    date: String,
}

// ── Request bodies ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PutBody<'a> {
    message: &'a str,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<&'a str>,
}

#[derive(Serialize)]
struct DeleteBody<'a> {
    message: &'a str,
    sha: &'a str,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Thin wrapper around the GitHub Contents API.
pub struct GitHubClient {
    client: Client,
    owner: String,
    repo: String,
    pat: String,
}

impl GitHubClient {
    /// `secrets_repo` should be in `owner/repo` format.
    pub fn new(secrets_repo: &str, pat: &str) -> Result<Self> {
        let (owner, repo) = secrets_repo.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("secrets_repo must be 'owner/repo', got '{}'", secrets_repo)
        })?;

        let client = Client::builder()
            .user_agent(format!("latch-rs/{}", BUILD_VERSION))
            .build()
            .context("Building reqwest client")?;

        Ok(Self {
            client,
            owner: owner.to_string(),
            repo: repo.to_string(),
            pat: pat.to_string(),
        })
    }

    fn contents_url(&self, path: &str) -> String {
        format!(
            "{}/repos/{}/{}/contents/{}",
            API_BASE, self.owner, self.repo, path
        )
    }

    fn commits_url(&self) -> String {
        format!("{}/repos/{}/{}/commits", API_BASE, self.owner, self.repo)
    }

    #[allow(dead_code)]
    fn tree_url(&self, git_ref: &str) -> String {
        format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            API_BASE, self.owner, self.repo, git_ref
        )
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.pat)
    }
}

#[async_trait]
impl RemoteStorage for GitHubClient {
    async fn push_file(&self, path: &str, content: &[u8], message: &str) -> Result<()> {
        let existing_sha = self.get_sha(path).await?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content);
        let body = PutBody {
            message,
            content: encoded,
            sha: existing_sha.as_deref(),
        };

        debug!("PUT {}", path);
        let resp = self
            .client
            .put(self.contents_url(path))
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .json(&body)
            .send()
            .await
            .context("GitHub PUT request failed")?;

        let status = resp.status();
        if status == StatusCode::OK || status == StatusCode::CREATED {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub PUT {} returned {}: {}", path, status, text);
        }
    }

    async fn pull_file(&self, path: &str) -> Result<Vec<u8>> {
        debug!("GET {}", path);
        let resp = self
            .client
            .get(self.contents_url(path))
            .header("Authorization", self.auth_header())
            // Request raw bytes to avoid JSON `content` truncation for larger files.
            .header("Accept", "application/vnd.github.raw")
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .send()
            .await
            .context("GitHub GET request failed")?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            bail!("Remote file not found: {}", path);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub GET {} returned {}: {}", path, status, text);
        }

        let bytes = resp
            .bytes()
            .await
            .context("Reading raw GitHub file bytes")?;
        Ok(bytes.to_vec())
    }

    async fn get_sha(&self, path: &str) -> Result<Option<String>> {
        debug!("SHA-check {}", path);
        let resp = self
            .client
            .get(self.contents_url(path))
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .send()
            .await
            .context("GitHub SHA request failed")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub GET {} returned {}: {}", path, status, text);
        }

        let body: ContentsResponse = resp
            .json()
            .await
            .context("Parsing GitHub contents for SHA")?;
        Ok(Some(body.sha))
    }

    async fn delete_file(&self, path: &str, message: &str) -> Result<()> {
        let Some(sha) = self.get_sha(path).await? else {
            return Ok(());
        };

        let body = DeleteBody { message, sha: &sha };

        debug!("DELETE {}", path);
        let resp = self
            .client
            .delete(self.contents_url(path))
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .json(&body)
            .send()
            .await
            .context("GitHub DELETE request failed")?;

        let status = resp.status();
        if status == StatusCode::OK || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub DELETE {} returned {}: {}", path, status, text);
        }
    }

    async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        let url = self.tree_url("HEAD");
        debug!("TREE {}", url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .send()
            .await
            .context("GitHub tree request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub tree returned {}: {}", status, text);
        }

        let tree: TreeResponse = resp.json().await.context("Parsing GitHub tree")?;
        let files = tree
            .tree
            .into_iter()
            .filter(|item| item.kind == "blob" && item.path.starts_with(prefix))
            .map(|item| item.path)
            .collect();
        Ok(files)
    }
}

#[async_trait]
impl RemoteStorageExt for GitHubClient {
    async fn list_commits(&self, path: &str, limit: usize) -> Result<Vec<CommitSummary>> {
        let url = self.commits_url();
        debug!("COMMITS {} (limit={})", path, limit);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .query(&[("path", path), ("per_page", &limit.to_string())])
            .send()
            .await
            .context("GitHub commits request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("GitHub commits returned {}: {}", status, text);
        }

        let items: Vec<CommitItem> = resp.json().await.context("Parsing GitHub commits")?;
        let summaries = items
            .into_iter()
            .map(|item| CommitSummary {
                sha: item.sha,
                message: item.commit.message,
                author: item.commit.author.name,
                date: item.commit.author.date,
            })
            .collect();
        Ok(summaries)
    }

    async fn pull_file_at_ref(&self, path: &str, git_ref: &str) -> Result<Vec<u8>> {
        let url = self.contents_url(path);
        debug!("GET {} @{}", path, git_ref);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .query(&[("ref", git_ref)])
            .send()
            .await
            .context("GitHub contents-at-ref request failed")?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            bail!("File '{}' not found at ref '{}'", path, git_ref);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            bail!(
                "GitHub GET {}@{} returned {}: {}",
                path,
                git_ref,
                status,
                text
            );
        }

        let body: ContentsResponse = resp.json().await.context("Parsing GitHub contents")?;
        let clean: String = body
            .content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&clean)
            .context("Base64-decoding GitHub file content")?;
        Ok(bytes)
    }
}
