use super::CredentialProvider;
use anyhow::Result;

const SERVICE: &str = "latch";

/// Stores credentials in the OS keyring.
///
/// Key names are namespaced by project:
/// - PAT  → `"{project}.pat"`
/// - key  → `"{project}.key"`
pub struct KeyringProvider;

impl KeyringProvider {
    fn entry(project: &str, kind: &str) -> Option<keyring::Entry> {
        keyring::Entry::new(SERVICE, &format!("{}.{}", project, kind)).ok()
    }

    fn get(project: &str, kind: &str) -> Option<String> {
        let entry = Self::entry(project, kind)?;
        match entry.get_password() {
            Ok(val) => Some(val),
            // `NoEntry` means it was never stored – not an error.
            Err(keyring::Error::NoEntry) => None,
            Err(_) => None,
        }
    }

    fn set(project: &str, kind: &str, value: &str) -> Result<()> {
        let entry = Self::entry(project, kind)
            .ok_or_else(|| anyhow::anyhow!("Failed to create keyring entry"))?;
        entry.set_password(value)?;
        Ok(())
    }

    /// Retrieve a value using the full `username` slot directly (used for
    /// env-scoped key slots like `"myapp.key.prod"`).
    pub fn get_raw(slot: &str) -> Option<String> {
        keyring::Entry::new(SERVICE, slot).ok()?.get_password().ok()
    }

    /// Persist a value using the full `username` slot directly.
    pub fn set_raw(slot: &str, value: &str) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE, slot)
            .map_err(|e| anyhow::anyhow!("Keyring entry creation failed: {}", e))?;
        entry.set_password(value)?;
        Ok(())
    }
}

impl CredentialProvider for KeyringProvider {
    fn get_pat(&self, project: &str) -> Option<String> {
        Self::get(project, "pat")
    }

    fn get_key(&self, project: &str) -> Option<String> {
        Self::get(project, "key")
    }

    fn set_credentials(&self, project: &str, pat: Option<&str>, key: Option<&str>) -> Result<()> {
        if let Some(p) = pat {
            Self::set(project, "pat", p)?;
        }
        if let Some(k) = key {
            Self::set(project, "key", k)?;
        }
        Ok(())
    }
}
