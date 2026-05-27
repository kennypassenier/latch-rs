use super::*;
use serde::{Deserialize, Serialize};

/// Global configuration - stores master secret and encryption key for projects
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GlobalConfig {
    /// Master secret for encrypting project keys
    #[serde(skip)]
    pub master_secret: Option<crate::crypto::SecretDerivationMode>,

    /// Encryption key in base64 format (used if master_secret not set)
    #[serde(rename = "key_b64", skip_serializing_if = "Option::is_none")]
    pub key_b64: Option<String>,

    /// GitHub PAT for the default project
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_pat: Option<String>,
}

impl GlobalConfig {
    /// Derive or load the global encryption key
    pub fn get_key(&self) -> anyhow::Result<crate::crypto::SecretKey> {
        // Try to derive key from master secret (for server projects)
        if let Some(secret_derivation_mode) = &self.master_secret {
            return Ok(crate::crypto::kdf::derive_key_from_secret(
                secret_derivation_mode,
                b"",
            ));
        }

        // Fall back to direct key from base64-encoded hex
        match &self.key_b64 {
            Some(k) => {
                let hex_str = k.replace(' ', "").replace(" ", "");
                let bytes = hex::decode(&hex_str)?;

                // Pad or truncate to 32 bytes for AES-256
                let mut padded = vec![0u8; 32];
                let len = bytes.len().min(32);
                padded[..len].copy_from_slice(&bytes[..len]);

                Ok(crate::crypto::SecretKey { data: padded })
            }
            None => Err(anyhow::anyhow!("No encryption key configured")),
        }
    }
}

/// Get the GitHub token for a project (either from config or env var)
pub fn get_github_token(project: &str) -> Option<String> {
    match crate::config::project::load(project) {
        Ok(cfg) => cfg.github_pat,
        Err(_) => std::env::var(format!("LATCH_GITHUB_{}", project.to_uppercase())).ok(),
    }
}

/// Parse global configuration from TOML content
pub fn parse(content: &str) -> Option<GlobalConfig> {
    if let Some(start) = content.find("[global]") {
        let end_marker = find_next_section(&content[start..])?;
        let section_content = &content[start + 8..start + 8 + end_marker];

        // Extract fields from the global section
        let key_b64 = extract_field(section_content, "key_b64");
        let github_pat = extract_field(section_content, "github_pat");

        Some(GlobalConfig {
            key_b64,
            master_secret: None, // Will be set separately for server projects
            github_pat,
        })
    } else {
        None
    }
}

/// Load global configuration from a config file path
pub fn load(path: &str) -> Result<GlobalConfig, crate::error::LatchError> {
    let content = std::fs::read_to_string(path).map_err(|e| crate::error::LatchError::Io(e))?;

    if let Some(cfg) = parse(&content) {
        Ok(cfg)
    } else {
        Err(crate::error::LatchError::Config(
            "No [global] section found in config".to_string(),
        ))
    }
}

/// Get the current global config (from default location)
pub fn get_config() -> Option<GlobalConfig> {
    let home = dirs::home_dir()?;
    let path = home.join(".config/latch/global.toml");

    if !path.exists() {
        // Try default location in home directory
        return None;
    }

    load(&path.to_string_lossy()).ok()
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
