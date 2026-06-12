use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn run_latch(args: &[&str]) -> (bool, String, String) {
    let home = TempDir::new().expect("temp home");
    let output = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .expect("run latch binary");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn root_help_lists_expected_commands() {
    let (ok, out, err) = run_latch(&["--help"]);
    assert!(ok, "--help should succeed, stderr={}", err);

    for command in [
        "clone", "login", "init", "commit", "push", "pull", "status", "rotate", "run", "key",
        "path", "project", "group", "history", "rollback", "update",
    ] {
        assert!(
            out.contains(command),
            "Root help should list command '{}'.\nOutput:\n{}",
            command,
            out
        );
    }
}

#[test]
fn alias_lock_maps_to_commit_help() {
    let (ok, out, err) = run_latch(&["lock", "--help"]);
    assert!(ok, "lock --help should succeed, stderr={}", err);
    assert!(
        out.to_lowercase().contains("commit") || out.contains("--env"),
        "lock alias should resolve to commit-style help.\nOutput:\n{}",
        out
    );
}

#[test]
fn alias_save_maps_to_push_help() {
    let (ok, out, err) = run_latch(&["save", "--help"]);
    assert!(ok, "save --help should succeed, stderr={}", err);
    assert!(
        out.to_lowercase().contains("push") || out.contains("--env"),
        "save alias should resolve to push-style help.\nOutput:\n{}",
        out
    );
}

#[test]
fn alias_unlock_maps_to_pull_help() {
    let (ok, out, err) = run_latch(&["unlock", "--help"]);
    assert!(ok, "unlock --help should succeed, stderr={}", err);
    assert!(
        out.to_lowercase().contains("pull") || out.contains("--dry-run"),
        "unlock alias should resolve to pull-style help.\nOutput:\n{}",
        out
    );
}

#[test]
fn pull_help_lists_one_shot_overrides() {
    let (ok, out, err) = run_latch(&["pull", "--help"]);
    assert!(ok, "pull --help should succeed, stderr={}", err);

    for flag in ["--PAT", "--KEY", "--REPO", "--project", "--sparse"] {
        assert!(
            out.contains(flag),
            "pull help should list '{}'.\nOutput:\n{}",
            flag,
            out
        );
    }
}

#[test]
fn state_help_lists_pull_command_flags() {
    let (ok, out, err) = run_latch(&["state", "--help"]);
    assert!(ok, "state --help should succeed, stderr={}", err);

    for flag in ["--pull-command", "--reveal", "--sparse", "--env"] {
        assert!(
            out.contains(flag),
            "state help should list '{}'.\nOutput:\n{}",
            flag,
            out
        );
    }
}

#[test]
fn subcommand_help_pages_are_accessible() {
    let cases = [
        ["clone", "--help"],
        ["project", "--help"],
        ["path", "--help"],
        ["group", "--help"],
        ["history", "--help"],
        ["rollback", "--help"],
        ["update", "--help"],
    ];

    for args in cases {
        let (ok, _out, err) = run_latch(&args);
        assert!(ok, "{:?} should succeed, stderr={}", args, err);
    }
}

#[test]
fn clone_offer_emits_json_and_persists_offer_file() {
    let home = TempDir::new().expect("temp home");
    let output = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args(["clone", "offer", "--ttl-minutes", "1"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .expect("run latch clone offer");

    assert!(
        output.status.success(),
        "clone offer should succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid offer json");

    let offer_id = v
        .get("offer_id")
        .and_then(|x| x.as_str())
        .expect("offer_id string");
    let created_at = v
        .get("created_at")
        .and_then(|x| x.as_u64())
        .expect("created_at u64");
    let expires_at = v
        .get("expires_at")
        .and_then(|x| x.as_u64())
        .expect("expires_at u64");
    let recipient_public_key = v
        .get("recipient_public_key")
        .and_then(|x| x.as_str())
        .expect("recipient_public_key string");

    assert!(
        expires_at > created_at,
        "offer expiry must be in the future"
    );
    assert!(
        !recipient_public_key.is_empty(),
        "recipient_public_key should not be empty"
    );

    let stored_offer = home
        .path()
        .join(".latch")
        .join("clone_offers")
        .join(format!("{}.json", offer_id));
    assert!(
        stored_offer.exists(),
        "stored offer should exist at {}",
        stored_offer.display()
    );
}

#[test]
fn clone_create_apply_restores_project_metadata() {
    let source_home = TempDir::new().expect("source home");
    let target_home = TempDir::new().expect("target home");

    // Seed source global config so clone create has project metadata to export.
    let source_latch = source_home.path().join(".latch");
    fs::create_dir_all(&source_latch).expect("create source .latch dir");
    fs::write(
        source_latch.join("config.toml"),
        r#"[[projects]]
name = "demo"
secrets_repo = "acme/secrets"
default_env = "dev"
"#,
    )
    .expect("write source global config");

    // 1) Offer on target.
    let offer_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args(["clone", "offer", "--ttl-minutes", "10"])
        .env("HOME", target_home.path())
        .env("XDG_CONFIG_HOME", target_home.path().join(".config"))
        .output()
        .expect("run clone offer");
    assert!(
        offer_out.status.success(),
        "offer failed: {}",
        String::from_utf8_lossy(&offer_out.stderr)
    );

    let offer_file = source_home.path().join("offer.json");
    fs::write(&offer_file, &offer_out.stdout).expect("write offer file");

    // 2) Create payload on source.
    let payload_file = source_home.path().join("payload.json");
    let create_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "clone",
            "create",
            "--offer-file",
            offer_file.to_str().expect("offer path utf8"),
            "--stdout-file",
            payload_file.to_str().expect("payload path utf8"),
            "--verify-code",
            "123456",
        ])
        .env("HOME", source_home.path())
        .env("XDG_CONFIG_HOME", source_home.path().join(".config"))
        .output()
        .expect("run clone create");
    assert!(
        create_out.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );
    assert!(payload_file.exists(), "payload file should be created");

    // 3) Apply payload on target.
    let apply_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "clone",
            "apply",
            "--payload-file",
            payload_file.to_str().expect("payload path utf8"),
            "--verify-code",
            "123456",
        ])
        .env("HOME", target_home.path())
        .env("XDG_CONFIG_HOME", target_home.path().join(".config"))
        .output()
        .expect("run clone apply");
    assert!(
        apply_out.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&apply_out.stderr)
    );

    // Target global config should now include the source project metadata.
    let target_cfg = target_home.path().join(".latch").join("config.toml");
    let cfg_text = fs::read_to_string(&target_cfg).expect("read target global config");
    assert!(cfg_text.contains("name = \"demo\""));
    assert!(cfg_text.contains("secrets_repo = \"acme/secrets\""));
    assert!(cfg_text.contains("default_env = \"dev\""));
}

#[test]
fn clone_apply_rejects_wrong_verify_code() {
    let source_home = TempDir::new().expect("source home");
    let target_home = TempDir::new().expect("target home");

    let source_latch = source_home.path().join(".latch");
    fs::create_dir_all(&source_latch).expect("create source .latch dir");
    fs::write(
        source_latch.join("config.toml"),
        r#"[[projects]]
name = "demo"
secrets_repo = "acme/secrets"
default_env = "dev"
"#,
    )
    .expect("write source global config");

    let offer_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args(["clone", "offer", "--ttl-minutes", "10"])
        .env("HOME", target_home.path())
        .env("XDG_CONFIG_HOME", target_home.path().join(".config"))
        .output()
        .expect("run clone offer");
    assert!(offer_out.status.success());

    let offer_file = source_home.path().join("offer.json");
    fs::write(&offer_file, &offer_out.stdout).expect("write offer file");

    let payload_file = source_home.path().join("payload.json");
    let create_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "clone",
            "create",
            "--offer-file",
            offer_file.to_str().expect("offer path utf8"),
            "--stdout-file",
            payload_file.to_str().expect("payload path utf8"),
            "--verify-code",
            "right-code",
        ])
        .env("HOME", source_home.path())
        .env("XDG_CONFIG_HOME", source_home.path().join(".config"))
        .output()
        .expect("run clone create");
    assert!(create_out.status.success());

    let apply_out = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "clone",
            "apply",
            "--payload-file",
            payload_file.to_str().expect("payload path utf8"),
            "--verify-code",
            "wrong-code",
        ])
        .env("HOME", target_home.path())
        .env("XDG_CONFIG_HOME", target_home.path().join(".config"))
        .output()
        .expect("run clone apply");

    assert!(
        !apply_out.status.success(),
        "apply should fail with wrong verify code"
    );
    let stderr = String::from_utf8_lossy(&apply_out.stderr).to_lowercase();
    assert!(
        stderr.contains("integrity") || stderr.contains("tag mismatch"),
        "expected integrity failure in stderr, got: {}",
        stderr
    );
}

#[test]
fn history_without_project_config_fails_with_guidance() {
    let (ok, _out, err) = run_latch(&["history"]);
    assert!(!ok, "history should fail without project config");

    let err_l = err.to_lowercase();
    assert!(
        err_l.contains("latch init") || err_l.contains(".latch/config.toml"),
        "error should guide user to init/config. stderr={} ",
        err
    );
}

#[test]
fn rollback_without_project_config_fails_with_guidance() {
    let (ok, _out, err) = run_latch(&["rollback"]);
    assert!(!ok, "rollback should fail without project config");

    let err_l = err.to_lowercase();
    assert!(
        err_l.contains("latch init") || err_l.contains(".latch/config.toml"),
        "error should guide user to init/config. stderr={} ",
        err
    );
}
