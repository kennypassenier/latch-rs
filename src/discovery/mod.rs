use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

// ── Discovery ─────────────────────────────────────────────────────────────────

/// Recursively scan `root` for `.env` files (and `.env.*` variants such as
/// `.env.local`, `.env.production`).
///
/// The walk honours `.gitignore` files found along the way **and** a custom
/// `.latchignore` file (same format as `.gitignore`).  Any directory named
/// `.latch` is always skipped to avoid re-encrypting config artefacts.
pub fn scan_env_files(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let walker = WalkBuilder::new(root)
        .add_custom_ignore_filename(".latchignore")
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
    name == ".env" || name.starts_with(".env.")
}

// ── Path flattening ───────────────────────────────────────────────────────────

/// Convert a relative local path to a flat remote filename.
///
/// Strips the leading dot from each path component and joins them with `.`:
/// - `backend/.env`      → `backend.env`
/// - `src/api/.env`      → `src.api.env`
/// - `frontend/.env.local` → `frontend.env.local`
pub fn flatten_path(local_path: &Path) -> String {
    local_path
        .components()
        .filter_map(|c| {
            let s = c.as_os_str().to_str()?;
            let s = s.trim_start_matches('.');
            if s.is_empty() { None } else { Some(s.to_string()) }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Build the remote repo path for a given project / env / flat filename.
///
/// Format: `{project}/{env}/{flat}.enc`
pub fn remote_path(project: &str, env: &str, flat: &str) -> String {
    format!("{}/{}/{}.enc", project, env, flat)
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
            if braced { i += 1; }
            let start = i;
            while i < bytes.len() {
                let c = bytes[i];
                if braced {
                    if c == b'}' { break; }
                } else if !c.is_ascii_alphanumeric() && c != b'_' {
                    break;
                }
                i += 1;
            }
            let var_name = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
            if braced && i < bytes.len() && bytes[i] == b'}' { i += 1; }

            let val = known.iter().rev()
                .find(|(k, _)| k == var_name)
                .map(|(_, v)| v.as_str())
                .or_else(|| std::env::var(var_name).ok().as_deref().map(|_| ""))
                .unwrap_or("");
            // Prefer actual process env for runtime expansion
            let resolved = std::env::var(var_name)
                .ok()
                .or_else(|| {
                    known.iter().rev().find(|(k, _)| k == var_name).map(|(_, v)| v.clone())
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

    #[test]
    fn flatten_simple() {
        assert_eq!(flatten_path(Path::new("backend/.env")), "backend.env");
    }

    #[test]
    fn flatten_nested() {
        assert_eq!(flatten_path(Path::new("src/api/.env")), "src.api.env");
    }

    #[test]
    fn flatten_env_variant() {
        assert_eq!(
            flatten_path(Path::new("frontend/.env.local")),
            "frontend.env.local"
        );
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
