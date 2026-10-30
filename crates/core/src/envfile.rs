//! The one env file per machine (2026-10-30, Kenny: "Een env-bestand").
//! `<latch home>/latch.env` holds `LATCH_PAT=…` and one `LATCH_KEY_…=<hex>`
//! line per key, i.e. exactly the variables the environment layer already
//! understands, so a service can load the same file with systemd's
//! `EnvironmentFile=` and latch reads it itself when no variable is set.
//!
//! Plain `NAME=VALUE` lines, `#` comments and blank lines. No quoting is
//! written; matching surrounding quotes are tolerated on read because
//! other tools add them. A line that is neither is a format error, never
//! silently dropped: this file holds credentials, and a half-understood
//! credentials file must stop the run, not shrink it.
//!
//! Every rewrite is atomic (the Files contract) and keeps the previous
//! content as `latch.env.bak` first.

use std::collections::BTreeMap;

use crate::error::LatchError;
use crate::platform::Platform;

pub const ENV_FILE: &str = "latch.env";

const HEADER: &str = "# latch credentials for this machine. Written by latch; keep mode 0600.\n\
# Safe to load as a systemd EnvironmentFile.\n";

pub fn path(p: &Platform) -> String {
    format!("{}/{}", p.latch_home, ENV_FILE)
}

/// Every variable in the file. A missing file reads as empty.
pub fn read_all(p: &Platform) -> Result<BTreeMap<String, String>, LatchError> {
    match p.files.read(&path(p))? {
        Some(raw) => parse(&raw),
        None => Ok(BTreeMap::new()),
    }
}

pub fn lookup(p: &Platform, var: &str) -> Result<Option<String>, LatchError> {
    Ok(read_all(p)?.remove(var))
}

/// Insert or replace one variable, keeping all others.
pub fn set(p: &Platform, var: &str, value: &str) -> Result<(), LatchError> {
    let mut map = read_all(p)?;
    map.insert(var.to_string(), value.to_string());
    write_all(p, &map)
}

pub fn remove(p: &Platform, var: &str) -> Result<(), LatchError> {
    let mut map = read_all(p)?;
    if map.remove(var).is_some() {
        write_all(p, &map)?;
    }
    Ok(())
}

/// Replace the whole file, keeping the previous content as `.bak`.
pub fn write_all(p: &Platform, map: &BTreeMap<String, String>) -> Result<(), LatchError> {
    for (name, value) in map {
        validate_pair(name, value)?;
    }
    let target = path(p);
    if let Some(existing) = p.files.read(&target)? {
        p.files
            .write_atomic(&format!("{}.bak", target), &existing)?;
    }
    p.files.write_atomic(&target, render(map).as_bytes())
}

pub fn render(map: &BTreeMap<String, String>) -> String {
    let mut out = String::from(HEADER);
    for (name, value) in map {
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

pub fn parse(raw: &[u8]) -> Result<BTreeMap<String, String>, LatchError> {
    let text = String::from_utf8_lossy(raw);
    let mut map = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(LatchError::Format {
                context: ENV_FILE.into(),
                detail: format!("line {} is not NAME=VALUE", idx + 1),
            });
        };
        let name = name.trim();
        if !valid_name(name) {
            return Err(LatchError::Format {
                context: ENV_FILE.into(),
                detail: format!("line {}: '{}' is not a variable name", idx + 1, name),
            });
        }
        map.insert(name.to_string(), unquote(value.trim()).to_string());
    }
    Ok(map)
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with(|c: char| c.is_ascii_digit())
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// What the writer can round-trip: a newline or a leading/trailing blank
/// in a value would be changed by the reader, so refuse it at write time.
fn validate_pair(name: &str, value: &str) -> Result<(), LatchError> {
    if !valid_name(name) {
        return Err(LatchError::other(
            format!("'{}' is not a valid variable name for {}", name, ENV_FILE),
            "this is a bug in latch — report it",
        ));
    }
    if value.contains('\n') || value.contains('\r') || value != value.trim() {
        return Err(LatchError::other(
            format!("the value for {} cannot be stored in {}", name, ENV_FILE),
            "values must be single-line without leading or trailing blanks",
        ));
    }
    Ok(())
}
