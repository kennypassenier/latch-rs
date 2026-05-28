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
    async fn push_file(
        &self,
        path: &str,
        content: &[u8],
        message: &str,
    ) -> Result<()>;

    /// Download the raw bytes of a file at `path`.
    async fn pull_file(&self, path: &str) -> Result<Vec<u8>>;

    /// Return the current blob SHA of `path`, or `None` if it doesn't exist.
    /// The SHA is required when updating an existing file via the GitHub API.
    async fn get_sha(&self, path: &str) -> Result<Option<String>>;

    /// List all paths under a given prefix (used when removing stale entries).
    #[allow(dead_code)]
    async fn list_files(&self, prefix: &str) -> Result<Vec<String>>;
}
