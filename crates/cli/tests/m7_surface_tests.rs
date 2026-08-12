//! M7 exhaustive sweep + D6 surface snapshot, against the real binary.
//!
//! M7's contract: without a TTY, EVERY command either completes or fails
//! loudly with a remedy — no prompt path reachable, hanging impossible.
//! The sweep runs each verb headless (piped stdio = no terminal) in a
//! scratch LATCH_HOME under a hard timeout.

use std::process::{Command, Stdio};

fn latch_headless(home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    // `timeout` turns a hang into exit 124 — the one exit code that
    // always fails this suite.
    let out = Command::new("timeout")
        .arg("20")
        .arg(env!("CARGO_BIN_EXE_latch"))
        .args(args)
        .env("LATCH_HOME", home)
        .env("HOME", home)
        .env_remove("LATCH_PAT")
        .env_remove("LATCH_PASSPHRASE")
        .env_remove("XDG_RUNTIME_DIR")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Every user-reachable verb (except `update`, which would hit the live
/// network and could genuinely self-update the test binary; its state
/// machine is exhaustively covered by mocked tests in l7).
const SWEEP: &[&[&str]] = &[
    &["login"],
    &["init"],
    &["commit"],
    &["push"],
    &["pull"],
    &["status"],
    &["run", "--", "true"],
    &["history"],
    &["rollback", "abc123"],
    &["verify"],
    &["state"],
    &["reset"], // would-be confirmation prompt: MUST hard-error headless
    &["diff"],
    &["edit"],
    &["example"],
    &["group", "list"],
    &["group", "resolve", "g", "--source", ".env"],
    &["group", "adopt", "g", "--from", ".env"],
    &["key", "show"],
    &["key", "rotate"],
    &["key", "backup", "out.bk"], // would-be passphrase prompt
    &["key", "restore", "out.bk"],
    &["clone", "offer"],
    &["clone", "create", "LATCH-OFFER:00"],
    &["clone", "apply", "LATCH-CLONE:00:00"], // would-be code confirm
    &["project", "list"],
    &["project", "bind", "nope"],
    &["project", "unbind", "nope"],
    &["path"],
    &["ui"], // needs a terminal: must refuse, not garble
];

#[test]
fn m7_every_verb_completes_or_fails_loudly_headless() {
    let tmp = tempdir::TempDir::new("latch-m7").unwrap();
    for args in SWEEP {
        let (code, stdout, stderr) = latch_headless(tmp.path(), args);
        assert_ne!(code, 124, "HANG: latch {:?} hit the timeout", args);
        assert_ne!(code, -1, "latch {:?} died without an exit code", args);
        if code != 0 {
            // AR6: every failure carries a remedy after '::'.
            assert!(
                stderr.contains("::") || stdout.contains("::"),
                "latch {:?} failed (exit {}) without a remedy line.\nstdout: {}\nstderr: {}",
                args,
                code,
                stdout,
                stderr
            );
        }
    }
}

// ── D6 · CLI surface snapshot ───────────────────────────────────────────

const HELP_TARGETS: &[&[&str]] = &[
    &["--help"],
    &["login", "--help"],
    &["init", "--help"],
    &["commit", "--help"],
    &["push", "--help"],
    &["pull", "--help"],
    &["status", "--help"],
    &["run", "--help"],
    &["history", "--help"],
    &["rollback", "--help"],
    &["verify", "--help"],
    &["state", "--help"],
    &["reset", "--help"],
    &["diff", "--help"],
    &["edit", "--help"],
    &["example", "--help"],
    &["group", "--help"],
    &["key", "--help"],
    &["ui", "--help"],
    &["project", "--help"],
    &["path", "--help"],
    &["update", "--help"],
    &["completions", "--help"],
    &["clone", "--help"],
];

fn surface_text() -> String {
    let tmp = tempdir::TempDir::new("latch-d6").unwrap();
    let mut out = String::new();
    for args in HELP_TARGETS {
        let (code, stdout, stderr) = latch_headless(tmp.path(), args);
        assert_eq!(code, 0, "help for {:?} failed: {}", args, stderr);
        out.push_str(&format!("═══ latch {}\n{}\n", args.join(" "), stdout));
    }
    out
}

/// The committed snapshot is the reviewable record of the CLI surface:
/// any wording/flag change shows up as a diff. Regenerate deliberately:
/// `UPDATE_CLI_SNAPSHOT=1 cargo test -p latch-cli cli_surface`.
#[test]
fn d6_cli_surface_matches_snapshot() {
    let snap_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snapshots/cli_surface.txt"
    );
    let current = surface_text();
    if std::env::var("UPDATE_CLI_SNAPSHOT").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(snap_path).parent().unwrap()).unwrap();
        std::fs::write(snap_path, &current).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(snap_path)
        .expect("snapshot missing — run once with UPDATE_CLI_SNAPSHOT=1");
    assert_eq!(
        stored, current,
        "CLI surface changed. If intended, regenerate with UPDATE_CLI_SNAPSHOT=1"
    );
}
