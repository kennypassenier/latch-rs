//! W1 · init: link a directory to a project and make sure its key exists.
//! Idempotent; init inside an already-linked tree is refused with
//! guidance.

use crate::config::{Config, Project};
use crate::credentials::CredStore;
use crate::error::LatchError;
use crate::keys;
use crate::platform::Platform;

#[derive(Debug)]
pub struct InitOutcome {
    pub project: String,
    pub created_key: bool,
    pub already_linked: bool,
    /// A starter `.latchignore` was left in the project (D8). False when
    /// the project already had one — an existing file is never touched.
    pub created_ignore: bool,
}

pub fn run(p: &Platform, dir: &str, name: Option<String>) -> Result<InitOutcome, LatchError> {
    let mut config = Config::load(p)?;

    if let Some(existing) = config.project_for_dir(dir) {
        if existing.dir == dir {
            return Ok(InitOutcome {
                project: existing.name.clone(),
                created_key: false,
                already_linked: true,
                created_ignore: write_starter_ignore(p, dir)?,
            });
        }
        return Err(LatchError::other(
            format!(
                "'{}' is inside project '{}' ({})",
                dir, existing.name, existing.dir
            ),
            "run latch from the project root, or unlink the parent first (latch project)",
        ));
    }

    let project = name.unwrap_or_else(|| {
        dir.rsplit('/')
            .next()
            .unwrap_or("project")
            .to_lowercase()
            .replace([' ', '_'], "-")
    });
    if project.is_empty()
        || !project
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(LatchError::other(
            format!("'{}' is not a valid project name", project),
            "use lowercase letters, digits and hyphens (or pass --name)",
        ));
    }

    let store = CredStore::new(p);
    let had_key = keys::get(&store, &project)?.is_some();
    keys::get_or_create(&store, &project)?;

    config.projects.push(Project {
        name: project.clone(),
        dir: dir.to_string(),
    });
    config.save(p)?;

    Ok(InitOutcome {
        project,
        created_key: !had_key,
        already_linked: false,
        created_ignore: write_starter_ignore(p, dir)?,
    })
}

/// Leave a starter `.latchignore` in the project (D8) — exclusive create,
/// so a project that already has one keeps its rules untouched.
fn write_starter_ignore(p: &Platform, dir: &str) -> Result<bool, LatchError> {
    p.files.try_create_exclusive(
        &format!("{}/{}", dir, crate::discovery::IGNORE_FILE),
        crate::discovery::IGNORE_TEMPLATE.as_bytes(),
    )
}
