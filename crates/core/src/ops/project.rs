//! D5 project management (list/bind/unbind) and M4 install path.

use crate::config::{Config, Project};
use crate::credentials::CredStore;
use crate::error::LatchError;
use crate::keys;
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

// ── D9 · repo-wide listing + project removal ────────────────────────────

#[derive(Debug)]
pub struct RepoProject {
    pub name: String,
    /// Local link dir on this machine, if any.
    pub linked_dir: Option<String>,
    /// Environments present in the repo, with ciphertext counts.
    pub envs: Vec<(String, usize)>,
}

/// D9: every project the secrets REPO knows about, cross-referenced with
/// the local links. The removal candidates are exactly the repo-only
/// entries the link-based `list` used to hide.
pub fn list_all(p: &Platform) -> Result<Vec<RepoProject>, LatchError> {
    let config = Config::load(p)?;
    let repo = super::consume::repo_handle(p)?;
    repo.ensure()?;
    let _ = repo.refresh(false)?; // offline: the cached clone serves (S5)

    let mut map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, usize>> =
        Default::default();
    for rel in repo.list("")? {
        let mut parts = rel.split('/');
        if let (Some(project), Some(env), Some(file)) = (parts.next(), parts.next(), parts.next()) {
            if project == "_groups" || !file.ends_with(".enc") {
                continue;
            }
            *map.entry(project.to_string())
                .or_default()
                .entry(env.to_string())
                .or_insert(0) += 1;
        }
    }
    // Locally-linked projects that never pushed anything still show up.
    for pr in &config.projects {
        map.entry(pr.name.clone()).or_default();
    }
    Ok(map
        .into_iter()
        .map(|(name, envs)| RepoProject {
            linked_dir: config
                .projects
                .iter()
                .find(|pr| pr.name == name)
                .map(|pr| pr.dir.clone()),
            envs: envs.into_iter().collect(),
            name,
        })
        .collect())
}

pub const REMOVE_ROTATION_TIP: &str = "git history keeps the removed ciphertexts readable with the kept key — if those secrets must truly die, rotate the underlying VALUES at their services";

/// Shown INSTEAD of the rotation tip when no key for this project is left
/// anywhere on this machine (reported by the homelab session, 2026-09-02,
/// after removing a project whose key had gone with the wiped keyring):
/// the generic tip urges a rotation round that would fix nothing, exactly
/// when the reader is already in trouble. Same failure as an error whose
/// remedy points at a machine that no longer exists — a message that is
/// true in the ordinary case and misleading in the one that hurts.
pub const REMOVE_NO_KEY_NOTE: &str = "no key for this project is left on this machine, so the removed ciphertexts in the git history cannot be opened by anyone here — nothing to rotate on their account";

#[derive(Debug)]
pub struct RemoveOutcome {
    pub name: String,
    pub removed_files: usize,
    pub envs: Vec<String>,
    /// Key slots deleted (only with purge_keys).
    pub purged_keys: Vec<String>,
    pub was_linked: bool,
    /// D9-D: printed by the shell so the history caveat is never silent.
    /// The honest closing note: the rotation tip only when a key that can
    /// actually still open the history is present, otherwise the note
    /// saying the history is already unreadable.
    pub rotation_tip: &'static str,
}

/// D9: retire a project everywhere the repo is concerned — every env's
/// ciphertexts (a NORMAL commit+push: history stays, per AR2), the local
/// link and per-machine marker. Keys stay unless `purge_keys` (D9-B
/// tiered: deleting them makes the git history unreadable forever).
///
/// Confirmation (D9-C): interactively the user must TYPE the exact
/// project name; without a terminal an explicit `yes` is required (M7 —
/// never hang, never a soft default).
pub fn remove(
    p: &Platform,
    name: &str,
    yes: bool,
    purge_keys: bool,
) -> Result<RemoveOutcome, LatchError> {
    let _lock = crate::lock::acquire(p, 10, || {})?;
    let repo = super::consume::repo_handle(p)?;
    repo.ensure()?;
    // Destructive: must operate on FRESH content (same rule as rotate).
    repo.refresh(true)?;

    // Everything the project owns in the repo, not only `<env>/<file>`
    // entries: v1 left a `manifest.json` at the project root, and the
    // `contains('/')` filter that derives environments used to skip it,
    // so a removed project stayed half-present on disk while
    // `latch project list` already called it gone (reported by the
    // homelab session, 2026-09-02).
    let files: Vec<String> = repo.list(name)?;
    if files.is_empty() {
        return Err(LatchError::other(
            format!("no project '{}' in the secrets repository", name),
            "latch project list shows what exists; a link without repo content is removed with 'latch project unbind'",
        ));
    }
    // Environments still come from the `<env>/<file>` shape only — a
    // root-level leftover names no environment.
    let mut envs: std::collections::BTreeSet<String> = Default::default();
    for rel in &files {
        if let Some((env, _)) = rel.split_once('/') {
            envs.insert(env.to_string());
        }
    }

    // D9-C confirmation gate.
    if !yes {
        if !p.prompt.interactive() {
            return Err(LatchError::other(
                format!("removing project '{}' needs confirmation", name),
                "pass --yes to confirm non-interactively (this deletes the project's ciphertexts from the secrets repo for every machine)",
            ));
        }
        let typed = p.prompt.line(&format!(
            "this permanently removes project '{}' ({} file(s), envs: {}) from the secrets repo — type the project name to confirm",
            name,
            files.len(),
            envs.iter().cloned().collect::<Vec<_>>().join(", ")
        ))?;
        if typed.trim() != name {
            return Err(LatchError::other(
                "confirmation does not match the project name — nothing was removed",
                "run again and type the exact project name",
            ));
        }
    }

    // Delete the whole prefix and publish as a normal commit (D9-D:
    // history untouched; S4 still guards a concurrently-moved remote).
    for rel in &files {
        repo.remove(&format!("{}/{}", name, rel))?;
    }
    repo.push(&format!("remove project {}", name), false)?;
    // git tracks no directories, so the emptied tree would stay behind in
    // the clone and keep the project looking half-present.
    p.files.remove_tree(&format!("{}/{}", repo.dir(), name))?;

    // Local cleanup: link + per-machine marker.
    let mut config = Config::load(p)?;
    let before = config.projects.len();
    config.projects.retain(|pr| pr.name != name);
    let was_linked = config.projects.len() != before;
    if was_linked {
        config.save(p)?;
    }
    p.files.remove(&format!("{}/seen/{}", p.latch_home, name))?;

    // D9-B: keys only go when explicitly asked.
    let mut purged = Vec::new();
    if purge_keys {
        let store = CredStore::new(p);
        let mut slots = vec![format!("key:{}", name), format!("key:{}#prev", name)];
        for env in &envs {
            slots.push(format!("key:{}.{}", name, env));
            slots.push(format!("key:{}.{}#prev", name, env));
        }
        for slot in slots {
            if store.get(&slot)?.is_some() {
                store.delete(&slot)?;
                purged.push(slot);
            }
        }
    }

    // Only warn about a readable history when a key that could read it
    // still exists here — purging the keys, or never having had them,
    // makes that warning false.
    let key_remains = keys::get(&CredStore::new(p), name)?.is_some();
    Ok(RemoveOutcome {
        name: name.to_string(),
        removed_files: files.len(),
        envs: envs.into_iter().collect(),
        purged_keys: purged,
        was_linked,
        rotation_tip: if key_remains {
            REMOVE_ROTATION_TIP
        } else {
            REMOVE_NO_KEY_NOTE
        },
    })
}
