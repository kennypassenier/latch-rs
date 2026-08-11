//! M1 · login: first-time setup on a machine. Takes PAT + repo (flags, or
//! prompts when interactive), VALIDATES them live with one `git ls-remote`
//! (the PAT travels via environment config, never argv — `ps` shows
//! nothing), then stores through the K4 chain and records the repo in
//! config. The very first stone of AR2: even login speaks git.

use crate::config::Config;
use crate::credentials::{CredStore, Source};
use crate::error::LatchError;
use crate::platform::Platform;

#[derive(Debug)]
pub struct LoginOutcome {
    pub repo: String,
    pub stored_in: Source,
}

pub fn run(
    p: &Platform,
    pat_arg: Option<String>,
    repo_arg: Option<String>,
) -> Result<LoginOutcome, LatchError> {
    let mut config = Config::load(p)?;

    let repo = match repo_arg.or_else(|| config.repo.clone()) {
        Some(r) => r,
        None => p
            .prompt
            .line("secrets repository (owner/name, e.g. kennypassenier/secrets)")?,
    };
    if !repo.contains('/') || repo.split('/').count() != 2 {
        return Err(LatchError::other(
            format!("'{}' is not an owner/name repository", repo),
            "use the GitHub owner/name form, e.g. kennypassenier/secrets",
        ));
    }

    let pat = match pat_arg.or_else(|| p.env.var("LATCH_PAT")) {
        Some(t) => t,
        None => p.prompt.passphrase("GitHub personal access token (PAT)")?,
    };

    validate(p, &pat, &repo)?;

    let store = CredStore::new(p);
    let stored_in = store.set("pat", pat.as_bytes())?;
    config.repo = Some(repo.clone());
    config.save(p)?;

    Ok(LoginOutcome { repo, stored_in })
}

/// One round-trip proves both the PAT and the repo (M1 validation). Auth
/// goes through GIT_CONFIG_* environment variables so the token never
/// appears in argv.
fn validate(p: &Platform, pat: &str, repo: &str) -> Result<(), LatchError> {
    let url = format!("https://github.com/{}.git", repo);
    let header = format!(
        "Authorization: Basic {}",
        base64_basic("x-access-token", pat)
    );
    let out = p.proc.run(
        "git",
        &["ls-remote", "--quiet", &url, "HEAD"],
        &[
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "http.extraHeader"),
            ("GIT_CONFIG_VALUE_0", &header),
        ],
        None,
    )?;
    if out.status != 0 {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(
            if stderr.contains("Authentication failed")
                || stderr.contains("401")
                || stderr.contains("403")
            {
                LatchError::other(
                format!("GitHub rejected the token for {}", repo),
                "check that the PAT is valid, unexpired, and has repo access (fine-grained: Contents read/write on the secrets repo)",
            )
            } else if stderr.contains("not found") || stderr.contains("404") {
                LatchError::other(
                    format!("repository {} not found (or the token cannot see it)", repo),
                    "check the owner/name spelling and the PAT's repository access",
                )
            } else {
                LatchError::other(
                    format!("could not reach {}: {}", repo, stderr.trim()),
                    "check your network connection and try again",
                )
            },
        );
    }
    Ok(())
}

/// Minimal base64 for the Basic auth header — no new dependency for 20
/// lines. Shared with the repo backend (AR2).
pub(crate) fn base64_basic(user: &str, pass: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{}:{}", user, pass);
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
