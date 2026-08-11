//! The sync verbs: W2 commit, W3 push, W4 pull, W5 status — all operating
//! on the AR2 clone through the AR9 path convention
//! `<project>/<env>/<flattened>.enc`.

use crate::config::Config;
use crate::credentials::CredStore;
use crate::discovery;
use crate::envelope;
use crate::error::LatchError;
use crate::groups;
use crate::keys;
use crate::lock;
use crate::platform::Platform;
use crate::repo::{PushOutcome, Repo};

pub const DEFAULT_ENV: &str = "dev";

pub struct ProjectCtx {
    pub name: String,
    pub dir: String,
}

/// Resolve which project a working directory belongs to (W1 linkage).
pub fn project_for(p: &Platform, cwd: &str) -> Result<ProjectCtx, LatchError> {
    let config = Config::load(p)?;
    let proj = config.project_for_dir(cwd).ok_or_else(|| {
        LatchError::other(
            format!("'{}' is not linked to a latch project", cwd),
            "run 'latch init' in the project root first",
        )
    })?;
    Ok(ProjectCtx {
        name: proj.name.clone(),
        dir: proj.dir.clone(),
    })
}

fn repo_handle<'a>(p: &'a Platform<'a>) -> Result<Repo<'a>, LatchError> {
    let config = Config::load(p)?;
    let repo_name = config.repo.ok_or_else(|| {
        LatchError::other(
            "no secrets repository configured",
            "run 'latch login' first",
        )
    })?;
    let store = CredStore::new(p);
    let pat = store
        .get("pat")?
        .map(|(v, _)| String::from_utf8_lossy(&v).to_string());
    Ok(Repo::new(p, &repo_name, pat))
}

// ── W2 commit ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CommitOutcome {
    /// (relative path, true = content changed)
    pub files: Vec<(String, bool)>,
    /// Files present in the clone but no longer locally — removed.
    pub removed: Vec<String>,
    /// W12 group sync results (fan-out happens inside the same commit).
    pub groups: Vec<groups::GroupReport>,
}

/// Encrypt the project's env files into the clone (no network). The file
/// list is returned so the shell can SHOW it (D1: no surprise pickups).
pub fn commit(p: &Platform, cwd: &str, env: &str) -> Result<CommitOutcome, LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;

    let store = CredStore::new(p);
    let key = keys::get_or_create(&store, &proj.name)?;

    let local = discovery::discover(p.files, &proj.dir)?;
    let prefix = format!("{}/{}", proj.name, env);

    let mut files = Vec::new();
    let mut kept = std::collections::BTreeSet::new();
    for rel in &local {
        let flat = discovery::flatten(rel)?;
        let enc_rel = format!("{}/{}.enc", prefix, flat);
        kept.insert(format!("{}.enc", flat));
        let plain = p
            .files
            .read(&format!("{}/{}", proj.dir, rel))?
            .ok_or_else(|| LatchError::other(format!("{} vanished mid-commit", rel), "retry"))?;
        if groups::parse_member(&plain).is_some() {
            // W12 member: the group engine below owns its stub + content;
            // here it only claims its slot so removal detection keeps it.
            continue;
        }
        // Unchanged? Compare against the decrypted clone version to keep
        // the git history free of no-op re-encryptions.
        let changed = match repo.read(&enc_rel)? {
            Some(existing) => match envelope::open(&key.key, &key.id, &existing, &enc_rel) {
                Ok(prev) => prev != plain,
                Err(_) => true,
            },
            None => true,
        };
        if changed {
            let sealed = envelope::seal(&key.key, &key.id, &plain)?;
            repo.write(&enc_rel, &sealed)?;
        }
        files.push((rel.clone(), changed));
    }

    // Locally-deleted files leave the intent at commit (data dirs stay —
    // this is just the env file's ciphertext).
    let mut removed = Vec::new();
    for existing in repo.list(&prefix)? {
        if !kept.contains(&existing) {
            repo.remove(&format!("{}/{}", prefix, existing))?;
            removed.push(discovery::unflatten(existing.trim_end_matches(".enc")));
        }
    }

    // W12: groups sync at commit time — one changed member becomes the
    // group content, everyone else is fanned out in this same commit.
    let group_reports = groups::sync_groups(p, &repo, env)?;

    Ok(CommitOutcome {
        files,
        removed,
        groups: group_reports,
    })
}

// ── W3 push ─────────────────────────────────────────────────────────────

pub fn push(p: &Platform, cwd: &str, env: &str, force: bool) -> Result<PushOutcome, LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    repo.push(&format!("push {}/{}", proj.name, env), force)
}

// ── W4 pull ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PullOutcome {
    pub written: Vec<String>,
    pub unchanged: Vec<String>,
    pub offline: bool,
}

/// Pull: refresh the clone (unless offline), decrypt EVERYTHING first
/// (all-or-nothing — one corrupt file writes nothing), then place files.
/// Local files that differ from the incoming content require `overwrite`
/// (S4): silent clobbering is designed out.
pub fn pull(
    p: &Platform,
    cwd: &str,
    env: &str,
    offline: bool,
    overwrite: bool,
) -> Result<PullOutcome, LatchError> {
    let _lock = lock::acquire(p, 10, || {})?;
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let fresh = if offline { false } else { repo.refresh(true)? };

    let store = CredStore::new(p);
    let key = keys::get(&store, &proj.name)?.ok_or_else(|| {
        LatchError::other(
            format!("no key for project '{}' on this machine", proj.name),
            "clone your credentials here (latch clone) or restore a key backup (latch key restore)",
        )
    })?;

    let prefix = format!("{}/{}", proj.name, env);
    // Phase 1: decrypt everything into memory.
    let mut incoming: Vec<(String, Vec<u8>)> = Vec::new();
    for enc_name in repo.list(&prefix)? {
        let Some(flat) = enc_name.strip_suffix(".enc") else {
            continue;
        };
        let rel = discovery::unflatten(flat);
        let sealed = repo
            .read(&format!("{}/{}", prefix, enc_name))?
            .expect("listed file readable");
        let plain = envelope::open(&key.key, &key.id, &sealed, &rel)?;
        // W12: a stub decrypts to its pragma line; the real content lives
        // once in _groups/<env>/<name>.enc under the group key.
        let plain = match groups::parse_member(&plain) {
            Some((name, _)) => {
                let body = groups::group_body(p, &repo, env, &name)?;
                groups::note_baseline(p, env, &name, &body, &format!("{}/{}", proj.name, rel))?;
                groups::member_file(&name, &body)
            }
            None => plain,
        };
        incoming.push((rel, plain));
    }

    // Phase 2: S4 check before any write.
    let mut conflicts = Vec::new();
    for (rel, plain) in &incoming {
        if let Some(local) = p.files.read(&format!("{}/{}", proj.dir, rel))? {
            if &local != plain {
                conflicts.push(rel.clone());
            }
        }
    }
    if !conflicts.is_empty() && !overwrite {
        return Err(LatchError::other(
            format!(
                "local changes would be overwritten: {} (S4)",
                conflicts.join(", ")
            ),
            "commit+push your local version first, or re-run with --overwrite to take the remote version",
        ));
    }

    // Phase 3: write.
    let mut written = Vec::new();
    let mut unchanged = Vec::new();
    for (rel, plain) in incoming {
        let path = format!("{}/{}", proj.dir, rel);
        match p.files.read(&path)? {
            Some(local) if local == plain => unchanged.push(rel),
            _ => {
                p.files.write_atomic(&path, &plain)?;
                written.push(rel);
            }
        }
    }

    Ok(PullOutcome {
        written,
        unchanged,
        offline: !fresh,
    })
}

// ── W5 status ───────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum FileState {
    Clean,
    Modified,
    LocalOnly,
    RemoteOnly,
}

#[derive(Debug)]
pub struct StatusOutcome {
    pub entries: Vec<(String, FileState)>,
}

pub fn status(p: &Platform, cwd: &str, env: &str) -> Result<StatusOutcome, LatchError> {
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let store = CredStore::new(p);
    let key = keys::get(&store, &proj.name)?;

    let prefix = format!("{}/{}", proj.name, env);
    let local = discovery::discover(p.files, &proj.dir)?;
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for rel in &local {
        let flat = discovery::flatten(rel)?;
        let enc_rel = format!("{}/{}.enc", prefix, flat);
        seen.insert(format!("{}.enc", flat));
        let local_content = p.files.read(&format!("{}/{}", proj.dir, rel))?;
        let member = local_content.as_deref().and_then(groups::parse_member);
        let state = match (&key, repo.read(&enc_rel)?, member) {
            // W12 member: clean when the local body matches the group
            // content; an unreadable group (missing key) reads as Modified
            // so it draws attention instead of lying "Clean".
            (_, Some(_), Some((name, body))) => match groups::group_body(p, &repo, env, &name) {
                Ok(gb) if gb == body => FileState::Clean,
                _ => FileState::Modified,
            },
            (Some(k), Some(sealed), None) => {
                let plain = envelope::open(&k.key, &k.id, &sealed, rel)?;
                if local_content.as_deref() == Some(plain.as_slice()) {
                    FileState::Clean
                } else {
                    FileState::Modified
                }
            }
            _ => FileState::LocalOnly,
        };
        entries.push((rel.clone(), state));
    }
    for existing in repo.list(&prefix)? {
        if !seen.contains(&existing) {
            entries.push((
                discovery::unflatten(existing.trim_end_matches(".enc")),
                FileState::RemoteOnly,
            ));
        }
    }
    Ok(StatusOutcome { entries })
}
