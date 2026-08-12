//! Rendering (G1): pure function of the model. Cyberpunk-leaning but
//! signal-first — effects never hide data. Masked values stay masked in
//! the buffer itself (G4), which the snapshot tests assert.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use ratatui::Frame;

use crate::model::*;

const NEON: Color = Color::Cyan;
const ACCENT: Color = Color::Magenta;
const DIM: Color = Color::DarkGray;
const WARN: Color = Color::Yellow;
const BAD: Color = Color::Red;
const GOOD: Color = Color::Green;

pub fn render(m: &Model, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(f.area());

    header(m, f, chunks[0]);
    match m.tab {
        Tab::Dashboard => dashboard(m, f, chunks[1]),
        Tab::Matrix => matrix(m, f, chunks[1]),
        Tab::Secrets => secrets(m, f, chunks[1]),
        Tab::History => history(m, f, chunks[1]),
        Tab::Doctor => doctor(m, f, chunks[1]),
        Tab::Clone => clone_wizard(m, f, chunks[1]),
    }
    footer(m, f, chunks[2]);
    if let Some(modal) = &m.modal {
        render_modal(modal, f);
    }
}

fn header(m: &Model, f: &mut Frame, area: Rect) {
    let mut spans = vec![
        Span::styled(" LATCH ", Style::default().fg(Color::Black).bg(NEON)),
        Span::raw(" "),
    ];
    for t in Tab::ALL {
        let style = if t == m.tab {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        spans.push(Span::styled(format!(" {} ", t.title()), style));
    }
    spans.push(Span::styled(
        format!(
            "  env:{}  repo:{}",
            m.env,
            m.world.repo.as_deref().unwrap_or("―")
        ),
        Style::default().fg(DIM),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn footer(m: &Model, f: &mut Frame, area: Rect) {
    let keys = match m.tab {
        Tab::Dashboard => "[↑↓] select  [enter] secrets  [c]ommit [p]ush p[u]ll [d]iff  [e]nv  [tab] next  [?] help  [q]uit",
        Tab::Matrix => "[↑↓] select  [e]nv cycle  [tab] next  [q]uit",
        Tab::Secrets => "[↑↓] row  [r]eveal  [a]dd  [m]odify  [x] delete  [s]ave  [d]iff  [q]uit",
        Tab::History => "[↑↓] version  [R]ollback  [q]uit",
        Tab::Doctor => "[v]erify  [R]otate key  [b]ackup keys  [B] restore  [l]ogin  [q]uit",
        Tab::Clone => "[t]arget  [→] scope project  [←] whole setup  [e]nv narrow  [enter] RUN  [q]uit",
    };
    let line = if m.status.is_empty() {
        Line::from(Span::styled(keys, Style::default().fg(DIM)))
    } else {
        Line::from(vec![
            Span::styled("▸ ", Style::default().fg(ACCENT)),
            Span::styled(&m.status, Style::default().fg(NEON)),
            Span::styled(format!("   {}", keys), Style::default().fg(DIM)),
        ])
    };
    f.render_widget(Paragraph::new(line), area);
}

fn state_style(state: &str) -> Style {
    match state {
        "clean" => Style::default().fg(GOOD),
        "modified" => Style::default().fg(WARN),
        s if s.contains("only") => Style::default().fg(ACCENT),
        _ => Style::default().fg(DIM),
    }
}

fn dashboard(m: &Model, f: &mut Frame, area: Rect) {
    let rows: Vec<Row> = m
        .world
        .projects
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let key = match p.keys.get(&m.env) {
                Some(Some(c)) => Span::styled(
                    format!("{}#{} [{}]", c.label, c.generation, c.source),
                    Style::default().fg(GOOD),
                ),
                _ => Span::styled("MISSING", Style::default().fg(BAD)),
            };
            let style = if i == m.sel_project {
                Style::default().bg(Color::Rgb(30, 30, 46))
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    p.name.clone(),
                    Style::default().fg(NEON).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(p.state.clone(), state_style(&p.state))),
                Cell::from(key),
                Cell::from(Span::styled(p.dir.clone(), Style::default().fg(DIM))),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["PROJECT", "STATE", "KEY", "DIR"])
            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(styled_block("projects"));
    f.render_widget(table, area);
}

fn matrix(m: &Model, f: &mut Frame, area: Rect) {
    // G3: projects × environments — which key from which source.
    let mut header_cells = vec![Cell::from("PROJECT")];
    for e in &m.world.envs {
        header_cells.push(Cell::from(e.as_str()));
    }
    let rows: Vec<Row> = m
        .world
        .projects
        .iter()
        .map(|p| {
            let mut cells = vec![Cell::from(Span::styled(
                p.name.clone(),
                Style::default().fg(NEON),
            ))];
            for e in &m.world.envs {
                cells.push(match p.keys.get(e) {
                    Some(Some(c)) => {
                        let marker = format!(
                            "{}{}#{}",
                            c.source,
                            if c.scoped { "*" } else { "" },
                            c.generation
                        );
                        Cell::from(Span::styled(marker, Style::default().fg(GOOD)))
                    }
                    _ => Cell::from(Span::styled("✗", Style::default().fg(BAD))),
                });
            }
            Row::new(cells)
        })
        .collect();
    let mut widths = vec![Constraint::Length(18)];
    widths.extend(m.world.envs.iter().map(|_| Constraint::Length(10)));
    let table = Table::new(rows, widths)
        .header(
            Row::new(header_cells).style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        )
        .block(styled_block(
            "key matrix — E env  F file  K keyring  * env-scoped  ✗ missing",
        ));
    f.render_widget(table, area);
}

fn secrets(m: &Model, f: &mut Frame, area: Rect) {
    let title = match m.selected_project() {
        Some(p) => format!(
            "secrets — {}/{}{}",
            p.name,
            m.env,
            if m.secrets_dirty { "  [UNSAVED]" } else { "" }
        ),
        None => "secrets".into(),
    };
    let rows: Vec<Row> = m
        .secrets
        .iter()
        .enumerate()
        .map(|(i, r)| {
            // G4: the value string only enters the buffer when revealed.
            let value = if r.revealed {
                Span::styled(r.value.clone(), Style::default().fg(WARN))
            } else {
                Span::styled("••••••••", Style::default().fg(DIM))
            };
            let style = if i == m.secrets_sel {
                Style::default().bg(Color::Rgb(30, 30, 46))
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(r.file.clone(), Style::default().fg(DIM))),
                Cell::from(Span::styled(r.key.clone(), Style::default().fg(NEON))),
                Cell::from(value),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(28),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["FILE", "KEY", "VALUE"])
            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(styled_block(&title));
    f.render_widget(table, area);
}

fn history(m: &Model, f: &mut Frame, area: Rect) {
    let rows: Vec<Row> = m
        .history
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let style = if i == m.history_sel {
                Style::default().bg(Color::Rgb(30, 30, 46))
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    h.reference.clone(),
                    Style::default().fg(ACCENT),
                )),
                Cell::from(Span::styled(
                    format!("t{}", h.time_unix),
                    Style::default().fg(DIM),
                )),
                Cell::from(h.message.clone()),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["REF", "WHEN", "MESSAGE"])
            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(styled_block("history — [R]ollback restores a version"));
    f.render_widget(table, area);
}

fn doctor(m: &Model, f: &mut Frame, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let d = &m.doctor;
    let yesno = |b: bool| {
        if b {
            Span::styled("yes", Style::default().fg(GOOD))
        } else {
            Span::styled("no", Style::default().fg(BAD))
        }
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("home       ", Style::default().fg(DIM)),
            Span::raw(d.latch_home.clone()),
        ]),
        Line::from(vec![
            Span::styled("repo       ", Style::default().fg(DIM)),
            Span::raw(d.repo.clone().unwrap_or_else(|| "― (login needed)".into())),
        ]),
        Line::from(vec![
            Span::styled("pat        ", Style::default().fg(DIM)),
            match &d.pat_source {
                Some(s) => Span::styled(s.clone(), Style::default().fg(GOOD)),
                None => Span::styled("missing", Style::default().fg(BAD)),
            },
        ]),
        Line::from(vec![
            Span::styled("keyring    ", Style::default().fg(DIM)),
            yesno(d.keyring_available),
        ]),
        Line::from(vec![
            Span::styled("cred file  ", Style::default().fg(DIM)),
            yesno(d.cred_file),
        ]),
        Line::from(vec![
            Span::styled("clone      ", Style::default().fg(DIM)),
            yesno(d.clone_exists),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(styled_block("state (W8)")),
        halves[0],
    );

    let rows: Vec<Row> = d
        .verify
        .iter()
        .map(|(file, verdict)| {
            let style = if verdict == "ok" {
                Style::default().fg(GOOD)
            } else {
                Style::default().fg(BAD).add_modifier(Modifier::BOLD)
            };
            Row::new(vec![
                Cell::from(file.clone()),
                Cell::from(Span::styled(verdict.clone(), style)),
            ])
        })
        .collect();
    let table = Table::new(rows, [Constraint::Min(20), Constraint::Min(16)])
        .header(
            Row::new(vec!["CIPHERTEXT", "VERDICT"])
                .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        )
        .block(styled_block("integrity audit (S6) — [v] re-run"));
    f.render_widget(table, halves[1]);
}

fn clone_wizard(m: &Model, f: &mut Frame, area: Rect) {
    let w = &m.wizard;
    let scope = match w.scope_project.and_then(|i| m.world.projects.get(i)) {
        None => "whole setup (all projects, all keys, pat, repo)".to_string(),
        Some(p) => match &w.scope_env {
            None => format!("project {} (its keys + group keys)", p.name),
            Some(e) => format!("project {} · env {} only", p.name, e),
        },
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "machine clone (M2) — E2E-encrypted over ssh",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(vec![
            Span::styled("target  ", Style::default().fg(DIM)),
            if w.target.is_empty() {
                Span::styled("― press [t]", Style::default().fg(BAD))
            } else {
                Span::styled(w.target.clone(), Style::default().fg(NEON))
            },
        ]),
        Line::from(vec![
            Span::styled("scope   ", Style::default().fg(DIM)),
            Span::styled(scope, Style::default().fg(NEON)),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "a 6-digit verify code binds both machines — a mismatch",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "means the payload is not yours: the apply refuses it.",
            Style::default().fg(DIM),
        )),
    ];
    if let Some(r) = &w.result {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            r.clone(),
            Style::default().fg(if r.starts_with('✗') { BAD } else { GOOD }),
        )));
    }
    f.render_widget(
        Paragraph::new(lines).block(styled_block("clone wizard")),
        area,
    );
}

fn styled_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(NEON))
        .title(Span::styled(
            format!("┤ {} ├", title),
            Style::default().fg(ACCENT),
        ))
}

fn render_modal(modal: &Modal, f: &mut Frame) {
    let area = centered(f.area(), 64, 14);
    f.render_widget(Clear, area);
    match modal {
        Modal::Help => {
            let lines: Vec<Line> = [
                "tab / shift-tab   switch screens",
                "arrows            navigate",
                "e                 cycle environment",
                "c / p / u / d     commit · push · pull · diff",
                "r                 reveal a secret row",
                "a / m / x / s     add · modify · delete · save vars",
                "R                 rollback (history) / rotate (doctor)",
                "b / B             backup / restore keys",
                "q                 quit",
            ]
            .iter()
            .map(|s| Line::raw(*s))
            .collect();
            f.render_widget(
                Paragraph::new(lines).block(styled_block("help — any key closes")),
                area,
            );
        }
        Modal::Input {
            title,
            buffer,
            mask,
            ..
        } => {
            let shown = if *mask {
                "•".repeat(buffer.len())
            } else {
                buffer.clone()
            };
            let lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled("> ", Style::default().fg(ACCENT)),
                    Span::styled(shown, Style::default().fg(NEON)),
                    Span::styled("▌", Style::default().fg(ACCENT)),
                ]),
                Line::raw(""),
                Line::from(Span::styled(
                    "[enter] confirm   [esc] cancel",
                    Style::default().fg(DIM),
                )),
            ];
            f.render_widget(Paragraph::new(lines).block(styled_block(title)), area);
        }
        Modal::Confirm { title, body, .. } => {
            let mut lines: Vec<Line> = body.iter().map(|s| Line::raw(s.clone())).collect();
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "[y/enter] yes   [any other key] no",
                Style::default().fg(DIM),
            )));
            f.render_widget(Paragraph::new(lines).block(styled_block(title)), area);
        }
        Modal::Conflict { detail, .. } => {
            let lines = vec![
                Line::from(Span::styled(
                    "the remote moved past your base (S4)",
                    Style::default().fg(WARN).add_modifier(Modifier::BOLD),
                )),
                Line::raw(detail.clone()),
                Line::raw(""),
                Line::from(Span::styled(
                    "[p] pull their changes first",
                    Style::default().fg(NEON),
                )),
                Line::from(Span::styled("[d] view the diff", Style::default().fg(NEON))),
                Line::from(Span::styled(
                    "[o] overwrite deliberately (history is kept)",
                    Style::default().fg(WARN),
                )),
                Line::from(Span::styled("[esc] do nothing", Style::default().fg(DIM))),
            ];
            f.render_widget(Paragraph::new(lines).block(styled_block("conflict")), area);
        }
        Modal::Diff { lines, revealed } => {
            let mut out: Vec<Line> = lines.iter().map(|s| Line::raw(s.clone())).collect();
            out.push(Line::raw(""));
            out.push(Line::from(Span::styled(
                if *revealed {
                    "[any key] close"
                } else {
                    "[r] reveal values   [any key] close"
                },
                Style::default().fg(DIM),
            )));
            let title = if *revealed {
                "diff (REVEALED)"
            } else {
                "diff (masked)"
            };
            f.render_widget(Paragraph::new(out).block(styled_block(title)), area);
        }
    }
}

fn centered(r: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(r.width.saturating_sub(2));
    let h = h.min(r.height.saturating_sub(2));
    Rect {
        x: r.x + (r.width - w) / 2,
        y: r.y + (r.height - h) / 2,
        width: w,
        height: h,
    }
}
