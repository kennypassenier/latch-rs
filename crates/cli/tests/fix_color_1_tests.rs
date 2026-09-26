//! fix-color-1: the `error:`/`warning:` labels were painted with raw ANSI
//! escapes unconditionally. Found on the Windows runtime check
//! (2026-09-26): PowerShell captured `[31merror:[0m` verbatim once stderr
//! was redirected. Colour belongs to a terminal only.

#[test]
fn error_label_has_no_escape_codes_when_stderr_is_not_a_terminal() {
    let home = std::env::temp_dir().join(format!("latch-fix-color-1-{}", std::process::id()));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_latch"))
        .arg("edit")
        .arg(".env")
        .env("LATCH_HOME", &home)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("run latch");
    let _ = std::fs::remove_dir_all(&home);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "edit outside a project must fail");
    assert!(stderr.contains("error:"), "stderr: {stderr}");
    assert!(
        !stderr.contains('\x1b'),
        "escape codes leaked into a pipe: {stderr:?}"
    );
}
