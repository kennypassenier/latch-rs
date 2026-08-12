//! D5 project management (list/bind/unbind) and M4 install path.

use crate::config::{Config, Project};
use crate::error::LatchError;
use crate::platform::Platform;

// ── D5 · latch project list / bind / unbind ─────────────────────────────

pub fn list(p: &Platform) -> Result<Vec<Project>, LatchError> {
    Ok(Config::load(p)?.projects)
}

/// Bind an EXISTING project name to a directory on this machine — the
/// "second machine" linking path (init creates; bind only links, so a
/// typo'd name can't silently create a parallel project).
pub fn bind(p: &Platform, name: &str, dir: &str) -> Result<(), LatchError> {
    let mut config = Config::load(p)?;
    if let Some(existing) = config.projects.iter_mut().find(|pr| pr.name == name) {
        existing.dir = dir.to_string();
        return config.save(p);
    }
    // Unknown locally: accept only if the repo knows it (otherwise the
    // user probably wants init).
    let repo = super::consume::repo_handle(p)?;
    repo.ensure()?;
    let known_in_repo = repo.list(name)?.iter().any(|f| f.contains('/'));
    if !known_in_repo {
        return Err(LatchError::other(
            format!("'{}' is not a known project (locally or in the repo)", name),
            "check the name (latch project list), or create it with 'latch init --name' in its directory",
        ));
    }
    config.projects.push(Project {
        name: name.to_string(),
        dir: dir.to_string(),
    });
    config.save(p)
}

/// Unlink a project from this machine. Keys and repo content stay — this
/// only forgets the directory linkage.
pub fn unbind(p: &Platform, name: &str) -> Result<(), LatchError> {
    let mut config = Config::load(p)?;
    let before = config.projects.len();
    config.projects.retain(|pr| pr.name != name);
    if config.projects.len() == before {
        return Err(LatchError::other(
            format!("'{}' is not linked on this machine", name),
            "latch project list shows what is",
        ));
    }
    config.save(p)
}

// ── M4 · latch path ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PathReport {
    /// Where updates will maintain the binary.
    pub install_path: String,
    /// Is that directory on $PATH right now?
    pub on_path: bool,
    /// Shell line to add when it is not.
    pub remedy: String,
}

/// Resolve the managed install path: config override wins, otherwise the
/// directory of the currently running executable (`exe` — passed in by
/// the shell; core stays ambient-free).
pub fn install_path(p: &Platform, exe: &str) -> Result<String, LatchError> {
    if let Some(dir) = Config::load(p)?.install_dir {
        let name = exe.rsplit('/').next().unwrap_or("latch");
        return Ok(format!("{}/{}", dir.trim_end_matches('/'), name));
    }
    Ok(exe.to_string())
}

pub fn path_report(p: &Platform, exe: &str) -> Result<PathReport, LatchError> {
    let install = install_path(p, exe)?;
    let dir = install
        .rsplit_once('/')
        .map(|(d, _)| d.to_string())
        .unwrap_or_else(|| ".".into());
    let on_path = p
        .env
        .var("PATH")
        .map(|path| path.split(':').any(|seg| seg == dir))
        .unwrap_or(false);
    Ok(PathReport {
        install_path: install,
        remedy: format!("export PATH=\"{}:$PATH\"  # add to your shell rc", dir),
        on_path,
    })
}
