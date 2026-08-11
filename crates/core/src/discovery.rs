//! .env discovery (D1) and reversible path flattening (D2).
//!
//! Discovery finds `.env` and `.env.*` files in a project tree (gitignore
//! honoured by the Files::walk adapter), excluding `.env.example` — those
//! are the D3 *output*, never secret input. The list is surfaced to the
//! user BEFORE anything is encrypted (D1 rule: no surprise pickups).
//!
//! Flattening maps a nested relative path to a flat repo name and back,
//! bijectively: `/` becomes `__`. To keep it reversible, paths that
//! themselves contain `__` are refused with a clear remedy — better a
//! rare explicit error than a silent collision (AR9 depends on this
//! round-tripping perfectly).

use crate::error::LatchError;
use crate::platform::Files;

/// Is this filename a secrets env file?
fn is_env_file(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if let Some(rest) = name.strip_prefix(".env.") {
        return rest != "example" && !rest.is_empty();
    }
    false
}

/// Find all env files under `project_dir` (relative paths, sorted).
pub fn discover(files: &dyn Files, project_dir: &str) -> Result<Vec<String>, LatchError> {
    Ok(files
        .walk(project_dir)?
        .into_iter()
        .filter(|rel| {
            let name = rel.rsplit('/').next().unwrap_or(rel);
            is_env_file(name)
        })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_matching() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
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
}
