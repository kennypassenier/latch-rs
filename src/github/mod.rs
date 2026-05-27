use anyhow::{Context, Result};

/// Create an unauthenticated GitHub client (for reading public repo info)
pub fn create_unauthenticated_client() -> anyhow::Result<octocrab::Octocrab> {
    Ok(octocrab::Octocrab::builder().build()?)
}
