//! The only module that touches latch-core (G1): every [`Cmd`] maps to
//! the SAME core call the CLI uses — the UI has no logic of its own.

use latch_core::credentials::{CredStore, Source};
use latch_core::error::LatchError;
use latch_core::ops::{clone, consume, edit_diff, init, keyops, login, sync};
use latch_core::platform::Platform;

use crate::model::*;

fn source_char(s: Source) -> char {
    match s {
        Source::EnvVar => 'E',
        Source::File => 'F',
        Source::Keyring => 'K',
    }
}

fn fail(e: LatchError) -> Msg {
    Msg::Op(OpResult::Failed(format!("{}", e)))
}

/// Run one command against the platform. `ui_cwd` is the directory the
/// UI was started from (used only for linking/doctoring context).
pub fn exec(cmd: Cmd, m: &Model, p: &Platform, ui_cwd: &str) -> Msg {
    let dir = m.selected_project().map(|pr| pr.dir.clone());
    let need_dir = || -> Result<String, LatchError> {
        dir.clone().ok_or_else(|| {
            LatchError::other(
                "no project selected",
                "link a project first (latch init in its directory)",
            )
        })
    };
    let out: Result<Msg, LatchError> = (|| {
        Ok(match cmd {
            Cmd::RefreshWorld => Msg::Op(OpResult::World(refresh_world(m, p)?)),
            Cmd::LoadSecrets => {
                let dir = need_dir()?;
                let mut rows = Vec::new();
                for rel in latch_core::discovery::discover(p.files, &dir)? {
                    if let Some(raw) = p.files.read(&format!("{}/{}", dir, rel))? {
                        for (k, v) in edit_diff::parse_env(&String::from_utf8_lossy(&raw)) {
                            rows.push(SecretRow {
                                file: rel.clone(),
                                key: k,
                                value: v,
                                revealed: false,
                            });
                        }
                    }
                }
                Msg::Op(OpResult::Secrets(rows))
            }
            Cmd::SaveSecrets { rows } => {
                let dir = need_dir()?;
                // Group rows per file, keep a W12 pragma first line if the
                // file already had one, then encrypted-commit (G4 = the
                // same machinery as commit).
                let mut by_file: std::collections::BTreeMap<String, Vec<&SecretRow>> =
                    Default::default();
                for r in &rows {
                    by_file.entry(r.file.clone()).or_default().push(r);
                }
                for (file, rows) in &by_file {
                    let path = format!("{}/{}", dir, file);
                    let mut content = String::new();
                    if let Some(existing) = p.files.read(&path)? {
                        let text = String::from_utf8_lossy(&existing).to_string();
                        if let Some(first) = text.lines().next() {
                            if first.trim().starts_with("# latch:group=") {
                                content.push_str(first);
                                content.push('\n');
                            }
                        }
                    }
                    for r in rows {
                        content.push_str(&format!("{}={}\n", r.key, r.value));
                    }
                    p.files.write_atomic(&path, content.as_bytes())?;
                }
                let out = sync::commit(p, &dir, &m.env)?;
                Msg::Op(OpResult::Done(format!(
                    "✓ saved + committed {} file(s) — push publishes",
                    out.files.len().max(by_file.len())
                )))
            }
            Cmd::Commit => {
                let dir = need_dir()?;
                let out = sync::commit(p, &dir, &m.env)?;
                let changed = out.files.iter().filter(|(_, c)| *c).count();
                Msg::Op(OpResult::Done(format!(
                    "✓ committed: {} changed, {} removed, {} group(s)",
                    changed,
                    out.removed.len(),
                    out.groups.len()
                )))
            }
            Cmd::Push { force } => {
                let dir = need_dir()?;
                match sync::push(p, &dir, &m.env, force, false) {
                    Ok(latch_core::repo::PushOutcome::Pushed) => {
                        Msg::Op(OpResult::Done("✓ pushed".into()))
                    }
                    Ok(latch_core::repo::PushOutcome::NothingToPush) => {
                        Msg::Op(OpResult::Done("nothing to push".into()))
                    }
                    Err(e) => {
                        let text = format!("{}", e);
                        if text.contains("S4") {
                            Msg::Op(OpResult::Conflict {
                                op: ConflictOp::Push,
                                detail: text,
                            })
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            Cmd::Pull { overwrite } => {
                let dir = need_dir()?;
                match sync::pull(p, &dir, &m.env, false, overwrite) {
                    Ok(out) => Msg::Op(OpResult::Done(format!(
                        "✓ pulled: {} written, {} unchanged{}{}",
                        out.written.len(),
                        out.unchanged.len(),
                        if out.offline { " (offline cache)" } else { "" },
                        if out.diverged {
                            " ⚠ unpushed local work — remote NOT taken in"
                        } else {
                            ""
                        }
                    ))),
                    Err(e) => {
                        let text = format!("{}", e);
                        if text.contains("S4") {
                            Msg::Op(OpResult::Conflict {
                                op: ConflictOp::Pull,
                                detail: text,
                            })
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            Cmd::Diff { reveal } => {
                let dir = need_dir()?;
                let diffs = edit_diff::diff(p, &dir, &m.env, reveal)?;
                let mut lines = Vec::new();
                for d in &diffs {
                    lines.push(format!("{}:", d.file));
                    for (k, change, old, new) in &d.entries {
                        let sym = match change {
                            edit_diff::Change::Added => '+',
                            edit_diff::Change::Removed => '-',
                            edit_diff::Change::Changed => '~',
                        };
                        match (old, new) {
                            (Some(o), Some(n)) => {
                                lines.push(format!("  {} {} {} -> {}", sym, k, o, n))
                            }
                            (None, Some(n)) => lines.push(format!("  {} {} = {}", sym, k, n)),
                            (Some(o), None) => lines.push(format!("  {} {} (was {})", sym, k, o)),
                            (None, None) => lines.push(format!("  {} {}", sym, k)),
                        }
                    }
                }
                if lines.is_empty() {
                    lines.push("no differences with the committed state".into());
                }
                Msg::Op(OpResult::DiffReady {
                    lines,
                    revealed: reveal,
                })
            }
            Cmd::LoadHistory => {
                let dir = need_dir()?;
                let rows = consume::history(p, &dir)?
                    .into_iter()
                    .map(|h| HistoryRow {
                        reference: h.reference,
                        time_unix: h.time_unix,
                        message: h.message,
                    })
                    .collect();
                Msg::Op(OpResult::History(rows))
            }
            Cmd::Rollback { reference } => {
                let dir = need_dir()?;
                consume::rollback(p, &dir, &m.env, &reference)?;
                Msg::Op(OpResult::Done(format!(
                    "✓ rolled back to {} — push publishes, pull applies locally",
                    reference
                )))
            }
            Cmd::LoadDoctor => {
                let st = consume::state(p)?;
                let verify = match consume::verify(p, None) {
                    Ok(v) => v
                        .entries
                        .into_iter()
                        .map(|(file, s)| {
                            let verdict = match s {
                                consume::VerifyState::Ok => "ok".to_string(),
                                consume::VerifyState::Corrupt => "CORRUPT".to_string(),
                                consume::VerifyState::NoKey { needed, generation } => {
                                    format!("no key ({}#{})", needed, generation)
                                }
                                consume::VerifyState::BadFormat(d) => format!("bad format: {}", d),
                            };
                            (file, verdict)
                        })
                        .collect(),
                    Err(e) => vec![("(audit failed)".to_string(), format!("{}", e))],
                };
                Msg::Op(OpResult::DoctorReady(DoctorSnapshot(Doctor {
                    latch_home: st.latch_home,
                    repo: st.repo,
                    pat_source: st.pat.map(|s| format!("{:?}", s)),
                    keyring_available: st.keyring_available,
                    cred_file: st.cred_file,
                    clone_exists: st.clone_exists,
                    verify,
                })))
            }
            Cmd::Rotate { env } => {
                let dir = need_dir()?;
                let out = keyops::rotate(p, &dir, env.as_deref())?;
                Msg::Op(OpResult::Done(format!(
                    "✓ {} -> generation {} ({} file(s)) ⚠ {}",
                    out.label,
                    out.new_generation,
                    out.reencrypted.len(),
                    out.caveat
                )))
            }
            Cmd::Backup { path } => {
                let out = keyops::backup(p, &path)?;
                let skipped = if out.skipped.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ⚠ {} key(s) not on this machine skipped",
                        out.skipped.len()
                    )
                };
                Msg::Op(OpResult::Done(format!(
                    "✓ {} credential(s) backed up to {}{}",
                    out.slots.len(),
                    out.path,
                    skipped
                )))
            }
            Cmd::Restore { path } => {
                let out = keyops::restore(p, &path)?;
                Msg::Op(OpResult::Done(format!(
                    "✓ {} credential(s) restored",
                    out.restored.len()
                )))
            }
            Cmd::Login { pat, repo } => {
                let out = login::run(p, Some(pat), Some(repo))?;
                let _ = init::run; // linking stays a CLI flow; ui_cwd kept for context
                let _ = ui_cwd;
                Msg::Op(OpResult::Done(format!(
                    "✓ logged in to {} (stored in {:?})",
                    out.repo, out.stored_in
                )))
            }
            Cmd::CloneTo {
                target,
                project,
                env,
            } => {
                let out = clone::clone_to(p, &target, project.as_deref(), env.as_deref())?;
                Msg::Op(OpResult::Done(format!(
                    "✓ {} credential(s) cloned to {} (code {})",
                    out.applied, target, out.code
                )))
            }
        })
    })();
    out.unwrap_or_else(fail)
}

fn refresh_world(m: &Model, p: &Platform) -> Result<WorldSnapshot, LatchError> {
    let config = latch_core::config::Config::load(p)?;
    let store = CredStore::new(p);

    // Environments: union of what the repo layout shows (if reachable).
    let mut envs: std::collections::BTreeSet<String> = [m.env.clone()].into();
    let repo_ok = latch_core::ops::consume::repo_handle(p);
    if let Ok(repo) = &repo_ok {
        if repo.ensure().is_ok() {
            for rel in repo.list("")? {
                let mut parts = rel.split('/');
                // Both `<project>/<env>/file` and `_groups/<env>/name`
                // carry the env as the second segment.
                if let (Some(_), Some(env), Some(_)) = (parts.next(), parts.next(), parts.next()) {
                    envs.insert(env.to_string());
                }
            }
        }
    }
    let envs: Vec<String> = envs.into_iter().collect();

    let mut projects = Vec::new();
    for proj in &config.projects {
        let mut info = ProjectInfo {
            name: proj.name.clone(),
            dir: proj.dir.clone(),
            ..Default::default()
        };
        // Key cell per env (G3): env-scoped slot first, then project key.
        for e in &envs {
            let scoped = format!("key:{}", latch_core::keys::label_for(&proj.name, Some(e)));
            let plain = format!("key:{}", proj.name);
            let cell = match store.get(&scoped)? {
                Some((raw, src)) if raw.len() >= 2 => Some(KeyCell {
                    label: latch_core::keys::label_for(&proj.name, Some(e)),
                    generation: u16::from_le_bytes([raw[0], raw[1]]),
                    source: source_char(src),
                    scoped: true,
                }),
                _ => match store.get(&plain)? {
                    Some((raw, src)) if raw.len() >= 2 => Some(KeyCell {
                        label: proj.name.clone(),
                        generation: u16::from_le_bytes([raw[0], raw[1]]),
                        source: source_char(src),
                        scoped: false,
                    }),
                    _ => None,
                },
            };
            info.keys.insert(e.clone(), cell);
        }
        // Sync state for the active env (G2).
        match sync::status(p, &proj.dir, &m.env) {
            Ok(st) => {
                let mut agg = "clean";
                for (file, state) in &st.entries {
                    let s = match state {
                        sync::FileState::Clean => "clean",
                        sync::FileState::Modified => "modified",
                        sync::FileState::LocalOnly => "local-only",
                        sync::FileState::RemoteOnly => "remote-only",
                    };
                    if s != "clean" {
                        agg = "modified";
                    }
                    info.files.push((file.clone(), s.to_string()));
                }
                if st.entries.is_empty() {
                    agg = "empty";
                }
                info.state = agg.to_string();
            }
            Err(e) => info.state = format!("? {}", e),
        }
        projects.push(info);
    }

    Ok(WorldSnapshot((config.repo, projects, envs)))
}
