use super::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Project configuration - stores encrypted key for each project
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_pat: Option<String>,
    #[serde(rename = "key_b64", skip_serializing_if = "Option::is_none")]
    pub key_b64: Option<String>,
}

impl ProjectConfig {
    /// Create a new project config with the given name
    pub fn with_name(name: &str) -> Self {
        Self {
            name: name.to_string(),
            github_pat: None,
            key_b64: None,
        }
    }

    /// Extract the encryption key from base64-encoded data
    pub fn extract_key(&self) -> anyhow::Result<crate::crypto::SecretKey> {
        let key = match &self.key_b64 {
            Some(k) => hex::decode(&k.replace(' ', ""))?,
            None => return Err(anyhow::anyhow!("No encryption key configured")),
        };

        // Pad or truncate to 32 bytes for AES-256
        let mut padded = vec![0u8; 32];
        let len = key.len().min(32);
        padded[..len].copy_from_slice(&key[..len]);

        Ok(crate::crypto::SecretKey { data: padded })
    }

    /// Get the GitHub PAT for this project (from config or env var)
    pub fn get_github_pat(&self, project: &str) -> Option<String> {
        self.github_pat
            .clone()
            .or_else(|| std::env::var(format!("LATCH_GITHUB_{}", project.to_uppercase())).ok())
    }
}

/// Get project config from a path
pub fn load(path: &str) -> Result<ProjectConfig, crate::error::LatchError> {
    let content = std::fs::read_to_string(path).map_err(|e| crate::error::LatchError::Io(e))?;

    if let Some(cfg) = parse(&content) {
        Ok(cfg)
    } else {
        Err(crate::error::LatchError::Config(
            "No [project] section found in config".to_string(),
        ))
    }
}

/// Load project configuration from a project name (reads from .config/latch/{project}.toml)
pub fn load_from_project_name(project: &str) -> Result<ProjectConfig, crate::error::LatchError> {
    let home = dirs::home_dir().ok_or_else(|| {
        crate::error::LatchError::Config("Could not determine home directory".to_string())
    })?;

    // Try project-specific config first
    if let Ok(cfg) = load(&format!(
        "{}/.config/latch/{}.toml",
        home.display(),
        project
    )) {
        return Ok(cfg);
    }

    // Fall back to current directory's .config/latch.toml
    let cwd_config_path = std::env::current_dir()?.join(".config/latch.toml");
    if cwd_config_path.exists() {
        if let Ok(proj_cfg) = load_from(&cwd_config_path.to_string_lossy()) {
            // Verify it has the correct project name
            if proj_cfg.name.as_str() == project {
                return Ok(proj_cfg);
            }
        }
    }

    Err(crate::error::LatchError::Config(format!(
        "No config found for project '{}'",
        project
    )))
}

/// Parse project configuration from TOML content
pub fn parse(content: &str) -> Option<ProjectConfig> {
    if let Some(start) = content.find("[project]") {
        let end_marker = find_next_section(&content[start..])?;
        let section_content = &content[start + 9..start + 9 + end_marker];

        // Extract fields from the project section
        let name = extract_field(section_content, "name");
        let github_pat = extract_field(section_content, "github_pat");
        let key_b64 = extract_field(section_content, "key_b64");

        Some(ProjectConfig {
            name: name.unwrap_or_default(),
            github_pat,
            key_b64,
        })
    } else {
        None
    }
}

/// Find the end of a TOML table section (returns bytes until next [section] or end)
fn find_next_section(content: &str) -> Option<usize> {
    let mut depth = 0;

    for (i, ch) in content.char_indices() {
        if ch == '[' {
            // Check if this is a table header (not nested array/table inside a string)
            if !content[..=i].ends_with('"') && !content[..=i].ends_with("'") {
                depth += 1;
            } else {
                depth -= 1; // Just a nested bracket
            }
        } else if ch == ']' && depth > 0 {
            depth -= 1;
        }

        if depth == 0 && i > 0 {
            return Some(i);
        }
    }

    Some(content.len())
}

fn extract_field(section: &str, field: &str) -> Option<String> {
    // Simple pattern matching for TOML field extraction
    if let Some(field_pos) = section.find(&format!("{}=", field)) {
        let rest = &section[field_pos..];

        // Look for value in a reasonable window (up to 2 lines)
        let two_lines: Vec<_> = rest
            .lines()
            .take(2)
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        if two_lines.len() == 0 {
            return None;
        }

        // Try to parse as various types
        if let Ok(val) = two_lines.join(" ").parse::<f64>() {
            return Some(val.to_string());
        } else if two_lines[0] == "true" || two_lines[0] == "false" {
            return Some(two_lines[0].to_string());
        }

        // Look for quoted string value
        if let Some(value) = extract_quoted_value(&two_lines.join(" ")) {
            return Some(value);
        }

        None
    } else {
        None
    }
}

/// Extract a quoted string value from TOML field assignment
fn extract_quoted_value(s: &str) -> Option<String> {
    let mut lines = s.lines().peekable();

    while let Some(line) = lines.peek() {
        if line.contains('=') {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() >= 2 {
                let value_part = parts[1..].join("=");
                return extract_string_value(&value_part);
            }
        }
        lines.next();
    }

    None
}

/// Extract a string value from its quotes
fn extract_string_value(s: &str) -> Option<String> {
    let trimmed = s.trim_start();

    if trimmed.is_empty() || (!trimmed.starts_with('"') && !trimmed.starts_with('\'')) {
        return None;
    }

    let quote_char = if trimmed.starts_with('"') { '"' } else { '\'' };

    if let Some(start) = trimmed.find(quote_char).ok() {
        let rest = &trimmed[start + 1..];
        let mut in_string = true;
        let mut escaped = false;
        let mut value = String::new();

        for ch in rest.chars() {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_char {
                break;
            } else {
                value.push(ch);
            }
        }

        Some(value)
    } else {
        None
    }
}
