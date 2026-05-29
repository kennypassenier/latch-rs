pub mod client;

use anyhow::Result;
use async_trait::async_trait;

/// Abstract interface for a remote secrets store.
///
/// The production implementation is [`client::GitHubClient`].
/// Tests can swap in a mock that satisfies this trait.
#[async_trait]
pub trait RemoteStorage: Send + Sync {
    /// Upload (create or overwrite) a file at `path`.
    async fn push_file(&self, path: &str, content: &[u8], message: &str) -> Result<()>;

    /// Download the raw bytes of a file at `path`.
    async fn pull_file(&self, path: &str) -> Result<Vec<u8>>;

    /// Return the current blob SHA of `path`, or `None` if it doesn't exist.
    /// The SHA is required when updating an existing file via the GitHub API.
    async fn get_sha(&self, path: &str) -> Result<Option<String>>;

    /// Delete a file at `path` if it exists.
    async fn delete_file(&self, path: &str, message: &str) -> Result<()>;

    /// List all paths under a given prefix (used when removing stale entries).
    #[allow(dead_code)]
    async fn list_files(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Summary of a single commit returned by [`RemoteStorage::list_commits`].
#[derive(Debug, Clone)]
pub struct CommitSummary {
    /// Full commit SHA.
    pub sha: String,
    /// Commit message (may be multi-line; use `.lines().next()` for the title).
    pub message: String,
    /// Author display name.
    pub author: String,
    /// ISO 8601 commit date string (e.g. `"2026-05-28T14:32:01Z"`).
    pub date: String,
}

/// Extended trait methods needed for history and rollback.
#[async_trait]
pub trait RemoteStorageExt: RemoteStorage {
    /// List the most recent commits that touched `path`, newest first.
    async fn list_commits(&self, path: &str, limit: usize) -> Result<Vec<CommitSummary>>;

    /// Download the raw bytes of a file at `path` as it existed at `git_ref`
    /// (a commit SHA, branch name, or tag).
    async fn pull_file_at_ref(&self, path: &str, git_ref: &str) -> Result<Vec<u8>>;
}
