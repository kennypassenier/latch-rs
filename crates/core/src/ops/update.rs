//! M5 self-update, homelab-grade: checksum verified against the release
//! manifest, the previous binary is kept beside the new one, and the new
//! binary must prove it RUNS (`--version`) before it replaces anything.
//! Any failure leaves the current install byte-identical.
//!
//! Network I/O travels through the injected Proc as `curl` invocations —
//! core stays free of an HTTP stack and the whole state machine is
//! testable with scripted responses.

use sha2::Digest;

use crate::error::LatchError;
use crate::platform::Platform;

pub const RELEASE_REPO: &str = "kennypassenier/latch-rs";
/// Asset names as the release workflow publishes them.
pub const ASSET_LINUX: &str = "latch-x86_64-unknown-linux-gnu";
pub const SUMS_ASSET: &str = "SHA256SUMS";

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    UpToDate {
        version: String,
    },
    Updated {
        from: String,
        to: String,
        /// Where the previous binary was kept.
        previous: String,
    },
}

fn curl(p: &Platform, url: &str) -> Result<Vec<u8>, LatchError> {
    let out = p.proc.run(
        "curl",
        &["-sSLf", url],
        &[("LATCH_UA", "latch-update")],
        None,
    )?;
    if out.status != 0 {
        return Err(LatchError::other(
            format!(
                "download failed: {} ({})",
                url,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            "check your network; releases live on GitHub",
        ));
    }
    Ok(out.stdout)
}

/// Pull `"tag_name": "vX.Y.Z"` out of the release JSON without a JSON
/// dependency dance — the field is flat and GitHub-stable.
fn parse_tag(body: &str) -> Option<String> {
    let idx = body.find("\"tag_name\"")?;
    let rest = &body[idx..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let inner = after.strip_prefix('"')?;
    Some(inner[..inner.find('"')?].to_string())
}

/// Find the expected hex digest for `asset` in a SHA256SUMS body
/// (`<hex>  <name>` per line).
fn sum_for(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        let hex = parts.next()?;
        let name = parts.next()?;
        (name == asset || name == format!("./{}", asset)).then(|| hex.to_lowercase())
    })
}

/// Run the update state machine against `exe` (the running binary's
/// managed path — see M4). `current_version` compares against the
/// release tag (with or without a leading v).
pub fn run(p: &Platform, current_version: &str, exe: &str) -> Result<UpdateOutcome, LatchError> {
    let api = format!(
        "https://api.github.com/repos/{}/releases/latest",
        RELEASE_REPO
    );
    let body = String::from_utf8_lossy(&curl(p, &api)?).to_string();
    let tag = parse_tag(&body).ok_or_else(|| LatchError::Format {
        context: "release metadata".into(),
        detail: "no tag_name in the GitHub response".into(),
    })?;
    let latest = tag.trim_start_matches('v').to_string();
    if latest == current_version.trim_start_matches('v') {
        return Ok(UpdateOutcome::UpToDate { version: latest });
    }

    let base = format!(
        "https://github.com/{}/releases/download/{}",
        RELEASE_REPO, tag
    );
    let sums_raw = curl(p, &format!("{}/{}", base, SUMS_ASSET))?;
    let sums = String::from_utf8_lossy(&sums_raw).to_string();
    let expected = sum_for(&sums, ASSET_LINUX).ok_or_else(|| LatchError::Format {
        context: SUMS_ASSET.into(),
        detail: format!("no entry for {}", ASSET_LINUX),
    })?;

    let binary = curl(p, &format!("{}/{}", base, ASSET_LINUX))?;

    // Gate 1: the checksum must match the manifest — a truncated or
    // tampered download aborts with the install untouched.
    let actual = hex::encode(sha2::Sha256::digest(&binary));
    if actual != expected {
        return Err(LatchError::other(
            format!(
                "checksum mismatch for {} (expected {}…, got {}…)",
                ASSET_LINUX,
                &expected[..12],
                &actual[..12]
            ),
            "the download is corrupt or tampered — nothing was changed; retry later",
        ));
    }

    // Gate 2: the new binary must actually run before it may replace
    // anything (the H5 lesson: a non-executing update bricks remote use).
    let staging = format!("{}/update-staging", p.latch_home);
    p.files.write_atomic(&staging, &binary)?;
    let chmod = p.proc.run("chmod", &["755", &staging], &[], None)?;
    if chmod.status != 0 {
        p.files.remove(&staging)?;
        return Err(LatchError::other(
            "could not mark the new binary executable",
            "check permissions on ~/.latch",
        ));
    }
    let probe = p.proc.run(&staging, &["--version"], &[], None)?;
    let probe_out = String::from_utf8_lossy(&probe.stdout).to_string();
    if probe.status != 0 || !probe_out.contains(&latest) {
        p.files.remove(&staging)?;
        return Err(LatchError::other(
            format!(
                "the downloaded binary does not run correctly (exit {}, said {:?})",
                probe.status,
                probe_out.trim()
            ),
            "nothing was changed — report this release; the previous binary keeps working",
        ));
    }

    // Keep the previous binary, then move the verified one into place.
    let previous = format!("{}.prev", exe);
    if let Some(current) = p.files.read(exe)? {
        p.files.write_atomic(&previous, &current)?;
        let _ = p.proc.run("chmod", &["755", &previous], &[], None);
    }
    p.files.write_atomic(exe, &binary)?;
    let chmod = p.proc.run("chmod", &["755", exe], &[], None)?;
    if chmod.status != 0 {
        return Err(LatchError::other(
            "installed but could not mark executable",
            format!("run: chmod 755 {}", exe),
        ));
    }
    p.files.remove(&staging)?;

    Ok(UpdateOutcome::Updated {
        from: current_version.to_string(),
        to: latest,
        previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_parsing() {
        assert_eq!(
            parse_tag(r#"{"url": "x", "tag_name": "v2.1.0", "assets": []}"#),
            Some("v2.1.0".into())
        );
        assert_eq!(parse_tag("{}"), None);
    }

    #[test]
    fn sums_parsing() {
        let sums = "abc123  latch-x86_64-unknown-linux-gnu\ndef456  other\n";
        assert_eq!(sum_for(sums, ASSET_LINUX), Some("abc123".into()));
        assert_eq!(sum_for(sums, "missing"), None);
    }
}
