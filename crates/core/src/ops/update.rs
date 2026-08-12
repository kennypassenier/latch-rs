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
/// Asset names as the release workflow publishes them, one per platform.
pub const ASSET_LINUX: &str = "latch-x86_64-unknown-linux-gnu";
pub const ASSET_WINDOWS: &str = "latch-x86_64-pc-windows-msvc.exe";
pub const SUMS_ASSET: &str = "SHA256SUMS";
pub const SIG_ASSET: &str = "SHA256SUMS.minisig";

/// The release-signing public key (D4), baked into the binary. The
/// checksum manifest must carry a valid minisign signature under this key
/// before ANY download is trusted — a compromised GitHub account cannot
/// forge it without the offline secret key.
///
/// SET-UP: run `minisign -G`, then replace the line below with the second
/// line of your `minisign.pub` (the base64 blob, no comment line). Until a
/// real key is set, `latch update` fails closed (refuses every release) —
/// which is safe. See docs/OPERATIONS_RUNBOOK.md R11.
pub const RELEASE_PUBKEY: &str =
    "RWQ00000000000000000000000000000000000000000000000000000000000000000000000000000";

/// The asset for the platform this binary was built for (M5 per-OS).
pub const fn asset_for_this_os() -> &'static str {
    if cfg!(windows) {
        ASSET_WINDOWS
    } else {
        ASSET_LINUX
    }
}

/// Compare two `X.Y.Z` versions; true when `candidate` is strictly newer
/// than `current` (D4 downgrade guard — a moved-back `latest` tag must
/// not "update" us to an older, vulnerable release).
fn is_strictly_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|n| n.trim().parse().unwrap_or(0))
            .collect()
    }
    let (c, cur) = (parts(candidate), parts(current));
    for i in 0..c.len().max(cur.len()) {
        let (a, b) = (
            c.get(i).copied().unwrap_or(0),
            cur.get(i).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    false
}

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

/// Executable suffix for the running platform (`.exe` on Windows).
fn exe_suffix() -> &'static str {
    if cfg!(windows) {
        ".exe"
    } else {
        ""
    }
}

/// D4: verify a minisign signature over `data` against `pubkey_b64`. Any
/// failure — bad key, bad signature, placeholder key still in place — is a
/// hard error, so the updater fails CLOSED.
fn verify_signature_with(
    data: &[u8],
    signature: &[u8],
    pubkey_b64: &str,
) -> Result<(), LatchError> {
    use minisign_verify::{PublicKey, Signature};
    let pk = PublicKey::from_base64(pubkey_b64).map_err(|_| {
        LatchError::other(
            "no valid release-signing key is configured in this build",
            "this latch build cannot verify updates; install a signed release built with a real RELEASE_PUBKEY (see OPERATIONS_RUNBOOK R11)",
        )
    })?;
    let sig = Signature::decode(&String::from_utf8_lossy(signature)).map_err(|_| {
        LatchError::other(
            "the release signature is malformed",
            "the SHA256SUMS.minisig asset is corrupt or missing — do not trust this release",
        )
    })?;
    pk.verify(data, &sig, false).map_err(|_| {
        LatchError::other(
            "release signature does NOT verify against the trusted key",
            "this release was not signed with your key — a compromised account cannot forge it; nothing was changed",
        )
    })
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
    run_with_pubkey(p, current_version, exe, RELEASE_PUBKEY)
}

/// The update state machine, with the trusted signing key injected. The
/// public entry point [`run`] passes the baked-in [`RELEASE_PUBKEY`];
/// tests pass a throwaway key so the signature gate can be exercised
/// end-to-end without the production key.
#[doc(hidden)]
pub fn run_with_pubkey(
    p: &Platform,
    current_version: &str,
    exe: &str,
    pubkey: &str,
) -> Result<UpdateOutcome, LatchError> {
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
    // D4 downgrade guard: only ever move FORWARD. A `latest` tag moved
    // back to an older release must not "update" us down to it.
    if !is_strictly_newer(&latest, current_version) {
        return Ok(UpdateOutcome::UpToDate {
            version: current_version.trim_start_matches('v').to_string(),
        });
    }

    let base = format!(
        "https://github.com/{}/releases/download/{}",
        RELEASE_REPO, tag
    );
    let asset = asset_for_this_os();
    let sums_raw = curl(p, &format!("{}/{}", base, SUMS_ASSET))?;

    // D4 GATE 0 — authenticity: the checksum manifest must carry a valid
    // minisign signature under the baked-in public key BEFORE we trust a
    // single byte it lists. This is what a compromised GitHub account
    // cannot forge (it lacks the offline secret key).
    let sig_raw = curl(p, &format!("{}/{}", base, SIG_ASSET))?;
    verify_signature_with(&sums_raw, &sig_raw, pubkey)?;

    let sums = String::from_utf8_lossy(&sums_raw).to_string();
    let expected = sum_for(&sums, asset).ok_or_else(|| LatchError::Format {
        context: SUMS_ASSET.into(),
        detail: format!("no entry for {}", asset),
    })?;

    let binary = curl(p, &format!("{}/{}", base, asset))?;

    // Gate 1: the checksum must match the (now authenticated) manifest —
    // a truncated or tampered download aborts with the install untouched.
    let actual = hex::encode(sha2::Sha256::digest(&binary));
    if actual != expected {
        return Err(LatchError::other(
            format!(
                "checksum mismatch for {} (expected {}…, got {}…)",
                asset,
                &expected[..12],
                &actual[..12]
            ),
            "the download is corrupt or tampered — nothing was changed; retry later",
        ));
    }

    // Gate 2: the new binary must actually run before it may replace
    // anything (the H5 lesson: a non-executing update bricks remote use).
    // Staged already-executable (cross-platform; on Windows the .exe
    // extension makes it runnable, on Unix write_executable sets 0755).
    let staging = format!("{}/update-staging{}", p.latch_home, exe_suffix());
    p.files.write_executable(&staging, &binary)?;
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
        p.files.write_executable(&previous, &current)?;
    }
    // K1: place the new binary atomically at 0755 — temp + rename
    // preserves the mode, so a power cut can never leave a
    // written-but-not-yet-executable binary (the old write-then-chmod had
    // exactly that window). If a restore is ever needed, the previous
    // binary is at <exe>.prev — 'mv <exe>.prev <exe>'.
    p.files.write_executable(exe, &binary)?;
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
