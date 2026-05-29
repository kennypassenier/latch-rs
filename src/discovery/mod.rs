use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

// ── Discovery ─────────────────────────────────────────────────────────────────

/// Recursively scan `root` for `.env` files (and `.env.*` variants such as
/// `.env.local`, `.env.production`).
///
/// The walk honours a custom `.latchignore` file (same format as `.gitignore`).
/// `.gitignore` is intentionally ignored so local secret files like `.env`
/// remain discoverable even when ignored by Git.
/// Any directory named
/// `.latch` is always skipped to avoid re-encrypting config artefacts.
pub fn scan_env_files(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let walker = WalkBuilder::new(root)
        .add_custom_ignore_filename(".latchignore")
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        // Dotfiles (e.g. .env) must NOT be skipped; the ignore crate hides
        // them by default.
        .hidden(false)
        .filter_entry(|e| {
            // Never descend into .latch/ or target/
            let name = e.file_name().to_str().unwrap_or("");
            name != ".latch" && name != "target"
        })
        .build();

    for entry in walker.flatten() {
        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            let name = entry.file_name().to_str().unwrap_or("");
            if is_env_filename(name) {
                results.push(entry.into_path());
            }
        }
    }

    results
}

/// Returns `true` for `.env`, `.env.local`, `.env.production`, etc.
fn is_env_filename(name: &str) -> bool {
    if name == ".env" {
        return true;
    }

    // Track .env variants, but never treat template/example files as secrets.
    if name.starts_with(".env.") {
        return !name.ends_with(".example") && !name.ends_with(".sample");
    }

    false
}

// ── Path flattening ───────────────────────────────────────────────────────────

/// Convert a relative local path to a flat remote filename.
///
/// Replaces path separators (`/` and `\\`) with `__` while preserving
/// filenames exactly, including leading dots:
/// - `backend/.env`         → `backend__.env`
/// - `src/api/.env`         → `src__api__.env`
/// - `frontend/.env.local`  → `frontend__.env.local`
pub fn flatten_path(local_path: &Path) -> String {
    local_path.to_string_lossy().replace(['/', '\\'], "__")
}

/// Build the remote repo path for a given project / env / flat filename.
///
/// Format: `{project}/{env}/{flat}.enc`
pub fn remote_path(project: &str, env: &str, flat: &str) -> String {
    format!("{}/{}/{}.enc", project, env, flat)
}

/// Build the local staging path for a standalone encrypted blob.
///
/// Format: `<project_root>/.latch/<env>/<flat>.enc`
pub fn local_blob_path(
    project_root: &std::path::Path,
    env: &str,
    flat: &str,
) -> std::path::PathBuf {
    project_root
        .join(".latch")
        .join(env)
        .join(format!("{}.enc", flat))
}

/// Build the local staging path for a clone-group encrypted blob.
///
/// Format: `<project_root>/.latch/<env>/group.<name>.enc`
pub fn local_group_blob_path(
    project_root: &std::path::Path,
    env: &str,
    group_name: &str,
) -> std::path::PathBuf {
    project_root
        .join(".latch")
        .join(env)
        .join(format!("group.{}.enc", group_name))
}

// ── .env.example generation ───────────────────────────────────────────────────

/// Generate a `.env.example` from the content of a `.env` file.
///
/// Rules:
/// - Blank lines are preserved.
/// - Comment lines (`# ...`) are preserved.
/// - `KEY=VALUE` lines become `KEY=` (value is stripped).
/// - Lines that don't contain `=` are preserved as-is (e.g. bare comments or
///   malformed entries).
pub fn generate_example(env_content: &str) -> String {
    env_content
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                line.to_string()
            } else if let Some(eq_pos) = line.find('=') {
                format!("{}=", &line[..eq_pos])
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write a `.env.example` file next to the given `.env` file.
pub fn write_example(env_path: &Path, content: &str) -> Result<()> {
    let example_path = env_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(".env.example");
    std::fs::write(&example_path, content)?;
    tracing::debug!("Wrote {}", example_path.display());
    Ok(())
}

// ── Clone group pragma support ─────────────────────────────────────────────

/// Parse the `# latch:group=<name>` pragma from the first line of a `.env` file.
///
/// Returns `Some(group_name)` if the first line is a valid group pragma,
/// `None` otherwise.  The group name is trimmed of surrounding whitespace.
///
/// ```
/// use std::path::Path;
/// // A file whose first line is "# latch:group=promtail_config" would return
/// // Some("promtail_config").
/// ```
pub fn read_pragma(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let first = content.lines().next()?;
    let group = first
        .trim()
        .strip_prefix("# latch:group=")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    let valid = group
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid { Some(group) } else { None }
}

/// Return `true` if the file contains at least one `KEY=VALUE` pair,
/// ignoring the optional pragma first line, blank lines, and comment lines.
///
/// Used during `latch push` to detect subscribe-intent members (files that
/// only carry the group pragma and no actual secrets yet).
pub fn has_key_value_pairs(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    // skip(1) skips the pragma line; it is harmless for non-pragma files too
    // since we only call this after confirming a pragma exists.
    content.lines().skip(1).any(|line| {
        let t = line.trim();
        !t.is_empty() && !t.starts_with('#') && t.contains('=')
    })
}

// ── Template variable expansion (8.4) ─────────────────────────────────────────

/// Expand `${VAR}` and `$VAR` references inside `.env` values.
///
/// Lookup order:
/// 1. Variables already resolved earlier in the same file (left-to-right).
/// 2. The current process environment.
///
/// Unknown variables expand to an empty string.
///
/// ```
/// use latch_rs::discovery::expand_env_vars;
/// let known = vec![("HOST".to_string(), "localhost".to_string())];
/// assert_eq!(expand_env_vars("${HOST}:5432", &known), "localhost:5432");
/// ```
pub fn expand_env_vars(value: &str, known: &[(String, String)]) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            let braced = i < bytes.len() && bytes[i] == b'{';
            if braced {
                i += 1;
            }
            let start = i;
            while i < bytes.len() {
                let c = bytes[i];
                if braced {
                    if c == b'}' {
                        break;
                    }
                } else if !c.is_ascii_alphanumeric() && c != b'_' {
                    break;
                }
                i += 1;
            }
            let var_name = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
            if braced && i < bytes.len() && bytes[i] == b'}' {
                i += 1;
            }

            let val = known
                .iter()
                .rev()
                .find(|(k, _)| k == var_name)
                .map(|(_, v)| v.as_str())
                .or_else(|| std::env::var(var_name).ok().as_deref().map(|_| ""))
                .unwrap_or("");
            // Prefer actual process env for runtime expansion
            let resolved = std::env::var(var_name)
                .ok()
                .or_else(|| {
                    known
                        .iter()
                        .rev()
                        .find(|(k, _)| k == var_name)
                        .map(|(_, v)| v.clone())
                })
                .unwrap_or_default();
            let _ = val; // replaced by resolved
            out.push_str(&resolved);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Apply template expansion to every value line in an `.env` file.
///
/// Variables defined earlier in the same file can be referenced by later lines.
/// Lines that are blank or comments are passed through unchanged.
#[allow(dead_code)]
pub fn expand_env_file(content: &str) -> String {
    let mut resolved: Vec<(String, String)> = Vec::new();
    let mut lines_out: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines_out.push(line.to_string());
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let raw_val = line[eq + 1..].to_string();
            let expanded = expand_env_vars(&raw_val, &resolved);
            resolved.push((key.clone(), expanded.clone()));
            lines_out.push(format!("{}={}", key, expanded));
        } else {
            lines_out.push(line.to_string());
        }
    }
    lines_out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flatten_simple() {
        assert_eq!(flatten_path(Path::new("backend/.env")), "backend__.env");
    }

    #[test]
    fn flatten_nested() {
        assert_eq!(flatten_path(Path::new("src/api/.env")), "src__api__.env");
    }

    #[test]
    fn flatten_env_variant() {
        assert_eq!(
            flatten_path(Path::new("frontend/.env.local")),
            "frontend__.env.local"
        );
    }

    #[test]
    fn pragma_requires_valid_group_name() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        std::fs::write(&path, "# latch:group=group-1\nA=1\n").expect("write");
        assert_eq!(read_pragma(&path).as_deref(), Some("group-1"));

        std::fs::write(&path, "# latch:group=bad name\nA=1\n").expect("write");
        assert!(read_pragma(&path).is_none());
    }

    #[test]
    fn ignore_example_and_sample_templates() {
        assert!(is_env_filename(".env"));
        assert!(is_env_filename(".env.prod"));
        assert!(!is_env_filename(".env.example"));
        assert!(!is_env_filename(".env.sample"));
    }

    #[test]
    fn scan_includes_gitignored_env_files() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        std::fs::write(root.join(".gitignore"), ".env\n.env.dev\n").expect("write .gitignore");
        std::fs::write(root.join(".env"), "A=1\n").expect("write .env");
        std::fs::write(root.join(".env.dev"), "A=2\n").expect("write .env.dev");
        std::fs::write(root.join(".env.example"), "A=\n").expect("write .env.example");

        let mut files = scan_env_files(root)
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        files.sort();

        assert_eq!(files, vec![".env".to_string(), ".env.dev".to_string()]);
    }

    #[test]
    fn example_strips_values() {
        let env = "SECRET=hunter2\nPORT=3000\n# comment\n\nEMPTY=";
        let ex = generate_example(env);
        assert!(ex.contains("SECRET=\n"));
        assert!(ex.contains("PORT=\n"));
        assert!(ex.contains("# comment"));
        assert!(!ex.contains("hunter2"));
        assert!(!ex.contains("3000"));
    }
}
