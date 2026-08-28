//! .env discovery (D1/D8) and reversible path flattening (D2).
//!
//! Discovery finds `.env` and `.env.*` files in a project tree, excluding
//! `.env.example` and `.env.sample` — those are the D3 *output*, never
//! secret input. The list is surfaced to the user BEFORE anything is
//! encrypted (D1 rule: no surprise pickups).
//!
//! Exclusions come from latch's own `.latchignore` plus the built-in
//! directory list below — never from `.gitignore` (D8, amending D1). A
//! `.env` is gitignored in every healthy project, which is the entire
//! reason latch exists; honouring that file made discovery skip exactly
//! the files it manages, silently (live bug, 2026-08-28).
//!
//! Flattening maps a nested relative path to a flat repo name and back,
//! bijectively: `/` becomes `__`. To keep it reversible, paths that
//! themselves contain `__` are refused with a clear remedy — better a
//! rare explicit error than a silent collision (AR9 depends on this
//! round-tripping perfectly).

use crate::error::LatchError;
use crate::platform::Files;

/// latch's own exclusion file (D8), gitignore format down to the
/// negations — but only latch reads it, so excluding a secret from git
/// and excluding it from latch stay separate decisions.
pub const IGNORE_FILE: &str = ".latchignore";

/// Directories discovery never descends into, with or without a
/// `.latchignore` (D8). Without this, the first commit in any Node
/// project offers dozens of stray `.env` files from third-party
/// packages. The list is a floor, not a cage: an explicit negation in
/// the project-root `.latchignore` (`!vendor/`) lifts an entry.
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".latch",
    "node_modules",
    "target",
    "vendor",
    ".venv",
    "venv",
];

/// The starter `.latchignore` that `latch init` leaves behind (D8), so
/// the mechanism is discoverable in the project itself instead of only
/// in the guide.
pub const IGNORE_TEMPLATE: &str = "\
# .latchignore — which files latch may NOT pick up (gitignore format).
#
# latch deliberately does NOT read .gitignore: your .env belongs there,
# and latch still has to find it. This file is the latch-only equivalent.
#
# Always skipped, no rule needed:
#   .git  .latch  node_modules  target  vendor  .venv  venv
# Undo one of those with a negation, e.g.:
#   !vendor/
#
# Examples:
#   fixtures/          # never look in this directory
#   .env.local         # never pick up this file
";

/// Is this filename a secrets env file?
fn is_env_file(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if let Some(rest) = name.strip_prefix(".env.") {
        // Templates are the D3 output; encrypting them back as secrets
        // is noise (v1 excluded both spellings, v2 had lost `.sample`).
        return rest != "example" && rest != "sample" && !rest.is_empty();
    }
    false
}

/// Find all env files under `project_dir` (relative paths, sorted).
pub fn discover(files: &dyn Files, project_dir: &str) -> Result<Vec<String>, LatchError> {
    Ok(env_files(files.walk(project_dir)?))
}

/// Discovery with every exclusion lifted — the `--no-ignore` diagnostic
/// (D8). It shows what the rules are hiding; it never changes what a
/// commit picks up.
pub fn discover_all(files: &dyn Files, project_dir: &str) -> Result<Vec<String>, LatchError> {
    Ok(env_files(files.walk_all(project_dir)?))
}

fn env_files(walked: Vec<String>) -> Vec<String> {
    walked
        .into_iter()
        .filter(|rel| {
            let name = rel.rsplit('/').next().unwrap_or(rel);
            is_env_file(name)
        })
        .collect()
}

/// What to tell someone whose project yielded nothing (D8). Finding zero
/// env files is almost always a mistake, and "0 file(s)" reported as
/// success is how the 2026-08-28 bug stayed invisible — so the message
/// names the directory, the rules in play and the way to look behind
/// them (standing rules 11 and 12).
pub fn no_files_hint(project_dir: &str) -> String {
    format!(
        "no env files found in {} — latch looks for .env and .env.* (never .env.example or .env.sample), always skips {}, and applies {} if present; run 'latch status --no-ignore' to see what the rules are hiding",
        project_dir,
        DEFAULT_IGNORED_DIRS.join(", "),
        IGNORE_FILE
    )
}

/// `api/.env` → `api__.env` (D2). Refuses `__` in the input.
pub fn flatten(rel_path: &str) -> Result<String, LatchError> {
    if rel_path.contains("__") {
        return Err(LatchError::other(
            format!("path '{}' contains '__' which the repo layout reserves", rel_path),
            "rename the directory/file to avoid double underscores — latch flattens '/' to '__' and must be able to reverse it",
        ));
    }
    Ok(rel_path.replace('/', "__"))
}

/// `api__.env` → `api/.env`.
pub fn unflatten(flat: &str) -> String {
    flat.replace("__", "/")
}

/// Turn a repo-derived flattened name back into a project-relative path,
/// REFUSING anything that would escape the project directory (S1). A
/// compromised repo can rename a legit ciphertext to a name like
/// `..__..__home__kenny__.bashrc.enc`; unflatten alone would hand back
/// `../../home/kenny/.bashrc` and pull would write outside the project.
/// Every read path that turns a repo filename into a local write target
/// MUST go through here, not bare `unflatten`.
pub fn unflatten_checked(flat: &str) -> Result<String, LatchError> {
    let rel = unflatten(flat);
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.starts_with('\\')
        || rel.contains(':')
        || rel.split('/').any(|c| c == ".." || c == ".")
    {
        return Err(LatchError::other(
            format!("repo entry '{}' maps to an unsafe path '{}'", flat, rel),
            "the secrets repo contains a file whose name escapes the project directory — inspect it (a healthy repo never has one); latch refuses to write outside the project",
        ));
    }
    Ok(rel)
}

/// Environment names index into repo paths (`<project>/<env>/…`) exactly
/// like project names do, so they get the same charset guard — otherwise
/// `--env ../../x` reads and writes outside the intended prefix.
pub fn validate_env(env: &str) -> Result<(), LatchError> {
    if env.is_empty()
        || env == "."
        || env == ".."
        || env.contains("..")
        || env.contains('/')
        || !env
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(LatchError::other(
            format!("'{}' is not a valid environment name", env),
            "environment names are letters, digits, '-', '_' and '.' (no path separators)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_matching() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file(".env.sample"));
        assert!(!is_env_file("env"));
        assert!(!is_env_file("config.env.example"));
        assert!(!is_env_file("notes.txt"));
    }

    #[test]
    fn flatten_round_trips() {
        for p in ["\u{2e}env", "api/.env", "a/b/c/.env.local", "worker/.env"] {
            assert_eq!(unflatten(&flatten(p).unwrap()), p, "{}", p);
        }
    }

    #[test]
    fn double_underscore_refused_not_corrupted() {
        let err = flatten("weird__dir/.env").unwrap_err();
        assert!(format!("{err}").contains("__"));
    }

    #[test]
    fn unflatten_checked_refuses_escapes() {
        // S1: the traversal payloads a malicious repo would use.
        for evil in [
            "..__..__..__home__kenny__.bashrc",
            "..__.ssh__authorized_keys",
            ".__.__x",
        ] {
            assert!(
                unflatten_checked(evil).is_err(),
                "must refuse escape: {evil}"
            );
        }
        // Legitimate names still round-trip.
        assert_eq!(unflatten_checked("api__.env").unwrap(), "api/.env");
        assert_eq!(unflatten_checked(".env").unwrap(), ".env");
    }

    #[test]
    fn env_name_validation() {
        for ok in ["dev", "prod", "staging-2", "feature_x", "v1.2"] {
            assert!(validate_env(ok).is_ok(), "{ok}");
        }
        for bad in ["", "../../x", "a/b", "..", "a/.."] {
            assert!(validate_env(bad).is_err(), "{bad}");
        }
    }
}
