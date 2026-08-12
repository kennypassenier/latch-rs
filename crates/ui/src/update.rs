//! Pure state transitions (G1): `update` never touches the platform —
//! it mutates the model and returns the [`Cmd`]s to run. Every test can
//! drive the whole UI by feeding messages and asserting emitted commands.

use crate::model::*;

pub fn update(m: &mut Model, msg: Msg) -> Vec<Cmd> {
    match msg {
        Msg::Op(op) => on_op(m, op),
        Msg::Key(k) => {
            if m.modal.is_some() {
                on_modal_key(m, k)
            } else {
                on_key(m, k)
            }
        }
    }
}

fn on_op(m: &mut Model, op: OpResult) -> Vec<Cmd> {
    match op {
        OpResult::World(WorldSnapshot((repo, projects, envs))) => {
            m.world = World {
                repo,
                projects,
                envs,
            };
            if m.sel_project >= m.world.projects.len() {
                m.sel_project = m.world.projects.len().saturating_sub(1);
            }
            vec![]
        }
        OpResult::Secrets(rows) => {
            m.secrets = rows;
            m.secrets_sel = 0;
            m.secrets_dirty = false;
            vec![]
        }
        OpResult::History(rows) => {
            m.history = rows;
            m.history_sel = 0;
            vec![]
        }
        OpResult::DoctorReady(DoctorSnapshot(d)) => {
            m.doctor = d;
            vec![]
        }
        OpResult::DiffReady { lines, revealed } => {
            m.modal = Some(Modal::Diff { lines, revealed });
            vec![]
        }
        OpResult::Done(status) => {
            m.status = status.clone();
            if m.tab == Tab::Clone {
                m.wizard.result = Some(status);
            }
            // Anything that finished may have changed the world.
            vec![Cmd::RefreshWorld]
        }
        OpResult::Conflict { op, detail } => {
            m.modal = Some(Modal::Conflict { op, detail });
            vec![]
        }
        OpResult::Failed(e) => {
            m.status = format!("✗ {}", e);
            if m.tab == Tab::Clone {
                m.wizard.result = Some(format!("✗ {}", e));
            }
            vec![]
        }
    }
}

fn cycle_tab(m: &mut Model, back: bool) -> Vec<Cmd> {
    let idx = Tab::ALL.iter().position(|t| *t == m.tab).unwrap_or(0);
    let n = Tab::ALL.len();
    m.tab = Tab::ALL[if back {
        (idx + n - 1) % n
    } else {
        (idx + 1) % n
    }];
    match m.tab {
        Tab::Secrets => vec![Cmd::LoadSecrets],
        Tab::History => vec![Cmd::LoadHistory],
        Tab::Doctor => vec![Cmd::LoadDoctor],
        _ => vec![],
    }
}

fn on_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    // Global keys first.
    match k {
        Key::Char('q') => {
            m.quit = true;
            return vec![];
        }
        Key::Char('?') => {
            m.modal = Some(Modal::Help);
            return vec![];
        }
        Key::Tab => return cycle_tab(m, false),
        Key::BackTab => return cycle_tab(m, true),
        Key::Char('e') if m.tab != Tab::Clone => {
            // Cycle the active environment (AZERTY-safe letters only);
            // on the Clone tab 'e' narrows the wizard scope instead.
            if !m.world.envs.is_empty() {
                let idx = m.world.envs.iter().position(|e| *e == m.env).unwrap_or(0);
                m.env = m.world.envs[(idx + 1) % m.world.envs.len()].clone();
                let mut cmds = vec![Cmd::RefreshWorld];
                if m.tab == Tab::Secrets {
                    cmds.push(Cmd::LoadSecrets);
                }
                return cmds;
            }
            return vec![];
        }
        _ => {}
    }
    match m.tab {
        Tab::Dashboard => on_dashboard_key(m, k),
        Tab::Matrix => on_list_nav(m, k),
        Tab::Secrets => on_secrets_key(m, k),
        Tab::History => on_history_key(m, k),
        Tab::Doctor => on_doctor_key(m, k),
        Tab::Clone => on_clone_key(m, k),
    }
}

fn on_list_nav(m: &mut Model, k: Key) -> Vec<Cmd> {
    let n = m.world.projects.len();
    match k {
        Key::Up if n > 0 => m.sel_project = (m.sel_project + n - 1) % n,
        Key::Down if n > 0 => m.sel_project = (m.sel_project + 1) % n,
        _ => {}
    }
    vec![]
}

fn on_dashboard_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    match k {
        Key::Enter => {
            m.tab = Tab::Secrets;
            vec![Cmd::LoadSecrets]
        }
        Key::Char('c') => vec![Cmd::Commit],
        Key::Char('p') => vec![Cmd::Push { force: false }],
        Key::Char('u') => vec![Cmd::Pull { overwrite: false }],
        Key::Char('d') => vec![Cmd::Diff { reveal: false }],
        _ => on_list_nav(m, k),
    }
}

fn on_secrets_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    let n = m.secrets.len();
    match k {
        Key::Up if n > 0 => {
            m.secrets_sel = (m.secrets_sel + n - 1) % n;
            vec![]
        }
        Key::Down if n > 0 => {
            m.secrets_sel = (m.secrets_sel + 1) % n;
            vec![]
        }
        // Reveal is per row and explicit (G4).
        Key::Char('r') if n > 0 => {
            m.secrets[m.secrets_sel].revealed = !m.secrets[m.secrets_sel].revealed;
            vec![]
        }
        Key::Char('a') => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::AddKey,
                title: "new variable NAME".into(),
                buffer: String::new(),
                mask: false,
            });
            vec![]
        }
        Key::Char('m') if n > 0 => {
            let row = &m.secrets[m.secrets_sel];
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::EditValue { row: m.secrets_sel },
                title: format!("new value for {}", row.key),
                buffer: String::new(),
                mask: false,
            });
            vec![]
        }
        Key::Char('x') if n > 0 => {
            let row = &m.secrets[m.secrets_sel];
            m.modal = Some(Modal::Confirm {
                action: ConfirmAction::DeleteRow { row: m.secrets_sel },
                title: format!("delete {}?", row.key),
                body: vec![
                    "the variable is removed from the local file".into(),
                    "and from the next encrypted commit".into(),
                ],
            });
            vec![]
        }
        Key::Char('s') if m.secrets_dirty => {
            vec![Cmd::SaveSecrets {
                rows: m.secrets.clone(),
            }]
        }
        Key::Char('d') => vec![Cmd::Diff { reveal: false }],
        _ => vec![],
    }
}

fn on_history_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    let n = m.history.len();
    match k {
        Key::Up if n > 0 => {
            m.history_sel = (m.history_sel + n - 1) % n;
            vec![]
        }
        Key::Down if n > 0 => {
            m.history_sel = (m.history_sel + 1) % n;
            vec![]
        }
        Key::Char('R') if n > 0 => {
            let row = &m.history[m.history_sel];
            m.modal = Some(Modal::Confirm {
                action: ConfirmAction::Rollback {
                    reference: row.reference.clone(),
                },
                title: format!("roll back to {}?", row.reference),
                body: vec![
                    "the clone is restored to that version".into(),
                    "push publishes it; pull applies it locally".into(),
                    "nothing is lost — this too becomes history".into(),
                ],
            });
            vec![]
        }
        _ => vec![],
    }
}

fn on_doctor_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    match k {
        Key::Char('v') => vec![Cmd::LoadDoctor],
        Key::Char('R') => {
            m.modal = Some(Modal::Confirm {
                action: ConfirmAction::Rotate { env: None },
                title: "rotate the project key?".into(),
                body: vec![
                    "a new key generation re-encrypts current files".into(),
                    "⚠ git history stays readable with the OLD key —".into(),
                    "full remediation also rotates the secret values".into(),
                ],
            });
            vec![]
        }
        Key::Char('b') => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::BackupPath,
                title: "write key backup to file".into(),
                buffer: String::new(),
                mask: false,
            });
            vec![]
        }
        Key::Char('B') => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::RestorePath,
                title: "restore key backup from file".into(),
                buffer: String::new(),
                mask: false,
            });
            vec![]
        }
        Key::Char('l') => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::LoginPat,
                title: "GitHub personal access token".into(),
                buffer: String::new(),
                mask: true,
            });
            vec![]
        }
        _ => on_list_nav(m, k),
    }
}

fn on_clone_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    match k {
        Key::Char('t') => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::CloneTarget,
                title: "ssh target (user@host)".into(),
                buffer: m.wizard.target.clone(),
                mask: false,
            });
            vec![]
        }
        // Scope: cycle whole-setup -> each project (arrows), env narrows.
        Key::Left => {
            m.wizard.scope_project = None;
            m.wizard.scope_env = None;
            vec![]
        }
        Key::Right | Key::Down => {
            let n = m.world.projects.len();
            if n > 0 {
                m.wizard.scope_project = Some(match m.wizard.scope_project {
                    None => 0,
                    Some(i) => (i + 1) % n,
                });
            }
            vec![]
        }
        Key::Char('e') => {
            // env narrowing inside the wizard (shadowed global cycle).
            if m.wizard.scope_project.is_some() {
                m.wizard.scope_env = match &m.wizard.scope_env {
                    None => m.world.envs.first().cloned(),
                    Some(cur) => {
                        let idx = m.world.envs.iter().position(|e| e == cur);
                        idx.and_then(|i| m.world.envs.get(i + 1).cloned())
                    }
                };
            }
            vec![]
        }
        Key::Enter => {
            if m.wizard.target.is_empty() {
                m.status = "set a target first ([t])".into();
                return vec![];
            }
            let project = m
                .wizard
                .scope_project
                .and_then(|i| m.world.projects.get(i))
                .map(|p| p.name.clone());
            let env = if project.is_some() {
                m.wizard.scope_env.clone()
            } else {
                None
            };
            m.wizard.result = Some("running…".into());
            vec![Cmd::CloneTo {
                target: m.wizard.target.clone(),
                project,
                env,
            }]
        }
        _ => vec![],
    }
}

fn on_modal_key(m: &mut Model, k: Key) -> Vec<Cmd> {
    let modal = m.modal.clone().expect("modal present");
    match modal {
        Modal::Help => {
            m.modal = None;
            vec![]
        }
        Modal::Diff {
            ref lines,
            revealed,
        } => match k {
            Key::Char('r') if !revealed => {
                let _ = lines;
                m.modal = None;
                vec![Cmd::Diff { reveal: true }]
            }
            Key::Esc | Key::Enter | Key::Char(_) => {
                m.modal = None;
                vec![]
            }
            _ => vec![],
        },
        Modal::Conflict { op, .. } => match k {
            Key::Esc => {
                m.modal = None;
                vec![]
            }
            Key::Char('p') => {
                m.modal = None;
                vec![Cmd::Pull { overwrite: false }]
            }
            Key::Char('d') => {
                m.modal = None;
                vec![Cmd::Diff { reveal: false }]
            }
            // The deliberate overwrite (G5): force for push, --overwrite
            // for pull — never the default, always this explicit key.
            Key::Char('o') => {
                m.modal = None;
                match op {
                    ConflictOp::Push => vec![Cmd::Push { force: true }],
                    ConflictOp::Pull => vec![Cmd::Pull { overwrite: true }],
                }
            }
            _ => vec![],
        },
        Modal::Confirm { action, .. } => match k {
            Key::Char('y') | Key::Enter => {
                m.modal = None;
                match action {
                    ConfirmAction::Rollback { reference } => vec![Cmd::Rollback { reference }],
                    ConfirmAction::Rotate { env } => vec![Cmd::Rotate { env }],
                    ConfirmAction::DeleteRow { row } => {
                        if row < m.secrets.len() {
                            m.secrets.remove(row);
                            if m.secrets_sel >= m.secrets.len() && m.secrets_sel > 0 {
                                m.secrets_sel -= 1;
                            }
                            m.secrets_dirty = true;
                        }
                        vec![]
                    }
                }
            }
            _ => {
                m.modal = None;
                vec![]
            }
        },
        Modal::Input {
            purpose,
            title,
            mut buffer,
            mask,
        } => match k {
            Key::Esc => {
                m.modal = None;
                vec![]
            }
            Key::Backspace => {
                buffer.pop();
                m.modal = Some(Modal::Input {
                    purpose,
                    title,
                    buffer,
                    mask,
                });
                vec![]
            }
            Key::Char(c) => {
                buffer.push(c);
                m.modal = Some(Modal::Input {
                    purpose,
                    title,
                    buffer,
                    mask,
                });
                vec![]
            }
            Key::Enter => {
                m.modal = None;
                on_input_submit(m, purpose, buffer)
            }
            _ => {
                m.modal = Some(Modal::Input {
                    purpose,
                    title,
                    buffer,
                    mask,
                });
                vec![]
            }
        },
    }
}

fn on_input_submit(m: &mut Model, purpose: InputPurpose, value: String) -> Vec<Cmd> {
    match purpose {
        InputPurpose::LoginPat => {
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::LoginRepo { pat: value },
                title: "secrets repository (owner/name)".into(),
                buffer: m.world.repo.clone().unwrap_or_default(),
                mask: false,
            });
            vec![]
        }
        InputPurpose::LoginRepo { pat } => vec![Cmd::Login { pat, repo: value }],
        InputPurpose::AddKey => {
            if value.trim().is_empty() {
                return vec![];
            }
            m.modal = Some(Modal::Input {
                purpose: InputPurpose::AddValue { key: value },
                title: "value".into(),
                buffer: String::new(),
                mask: false,
            });
            vec![]
        }
        InputPurpose::AddValue { key } => {
            let file = m
                .secrets
                .first()
                .map(|r| r.file.clone())
                .unwrap_or_else(|| ".env".into());
            m.secrets.push(SecretRow {
                file,
                key: key.trim().to_string(),
                value,
                revealed: false,
            });
            m.secrets_dirty = true;
            vec![]
        }
        InputPurpose::EditValue { row } => {
            if let Some(r) = m.secrets.get_mut(row) {
                r.value = value;
                m.secrets_dirty = true;
            }
            vec![]
        }
        InputPurpose::BackupPath => vec![Cmd::Backup { path: value }],
        InputPurpose::RestorePath => vec![Cmd::Restore { path: value }],
        InputPurpose::CloneTarget => {
            m.wizard.target = value;
            vec![]
        }
    }
}
