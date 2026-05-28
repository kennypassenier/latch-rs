use super::CredentialProvider;
use anyhow::Result;

/// Reads credentials from environment variables:
/// - `LATCH_PAT`  – GitHub Personal Access Token
/// - `LATCH_KEY`  – hex-encoded 32-byte encryption key
pub struct EnvVarProvider;

impl CredentialProvider for EnvVarProvider {
    fn get_pat(&self, _project: &str) -> Option<String> {
        std::env::var("LATCH_PAT").ok()
    }

    fn get_key(&self, _project: &str) -> Option<String> {
        std::env::var("LATCH_KEY").ok()
    }

    fn set_credentials(
        &self,
        _project: &str,
        _pat: Option<&str>,
        _key: Option<&str>,
    ) -> Result<()> {
        anyhow::bail!("Cannot persist credentials via environment variables")
    }

    fn delete_credentials(&self, _project: &str) -> Result<()> {
        anyhow::bail!("Cannot delete credentials from environment variables")
    }
}
