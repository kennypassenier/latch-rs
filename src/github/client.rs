use super::RemoteStorage;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::debug;

const API_BASE: &str = "https://api.github.com";
const ACCEPT_HEADER: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "2022-11-28";

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

// ── Request body ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PutBody<'a> {
    message: &'a str,
    content: String,          // base64-encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<&'a str>,     // required when updating an existing file
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Thin wrapper around the GitHub Contents API.
///
/// Uses `Authorization: Bearer <pat>` with the required `Accept` and
/// `X-GitHub-Api-Version` headers on every request.
pub struct GitHubClient {
    client: Client,
    owner: String,
    repo: String,
    pat: String,
}

impl GitHubClient {
    /// `secrets_repo` should be in `"owner/repo"` format.
    pub fn new(secrets_repo: &str, pat: &str) -> Result<Self> {
        let (owner, repo) = secrets_repo
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("secrets_repo must be 'owner/repo', got '{}'", secrets_repo))?;

        let client = Client::builder()
            .user_agent(concat!("latch-rs/", env!("CARGO_PKG_VERSION")))
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

    #[allow(dead_code)]
    fn tree_url(&self, branch: &str) -> String {
        format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            API_BASE, self.owner, self.repo, branch
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
            .header("Accept", ACCEPT_HEADER)
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

        let body: ContentsResponse = resp.json().await.context("Parsing GitHub contents response")?;
        // GitHub base64 content includes newlines every 60 chars – strip them.
        let clean = body.content.replace('\n', "").replace('\r', "");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&clean)
            .context("Decoding base64 content from GitHub")?;
        Ok(bytes)
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

        let body: ContentsResponse = resp.json().await.context("Parsing GitHub contents for SHA")?;
        Ok(Some(body.sha))
    }

    async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        // Use the git trees API with recursive=1 to list all files.
        // We fetch the default branch tree.  Prefix filtering is done client-side.
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
