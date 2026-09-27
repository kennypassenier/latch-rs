//! fix-win-update-1: `latch update` on Windows failed at the last step with
//! "rename to ...\latch.exe: Access is denied. (os error 5)". Found on the
//! Windows runtime check (2026-09-27, checklist §5) updating 2.4.0 to the
//! signed 2.5.1: Windows refuses to replace the image of a running
//! process, and the binary being replaced is always the one running.
//! Moving a running image aside IS allowed, so the old file is renamed out
//! of the way first and the new one takes its place.

/// Runs where it matters: a running executable is replaced in place.
#[cfg(windows)]
#[test]
fn a_running_executable_can_be_replaced() {
    use latch_core::platform::real::RealFiles;
    use latch_core::platform::Files;

    let tmp = tempdir::TempDir::new("latch-fix-win-update-1").unwrap();
    let target = tmp.path().join("ping-copy.exe");
    std::fs::copy(r"C:\Windows\System32\PING.EXE", &target).unwrap();
    let mut running = std::process::Command::new(&target)
        .args(["-n", "6", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let path = target.display().to_string();
    let replaced = RealFiles.write_executable(&path, b"new image");
    let _ = running.kill();
    let _ = running.wait();
    replaced.expect("replacing a running executable");
    assert_eq!(std::fs::read(&target).unwrap(), b"new image");
}

/// Everywhere: replacing an executable that is not running still works
/// and leaves no temp file behind.
#[test]
fn an_idle_executable_is_replaced_without_leftovers() {
    use latch_core::platform::real::RealFiles;
    use latch_core::platform::Files;

    let tmp = tempdir::TempDir::new("latch-fix-win-update-1").unwrap();
    let target = tmp.path().join("tool");
    std::fs::write(&target, b"old").unwrap();
    let path = target.display().to_string();
    RealFiles.write_executable(&path, b"new").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    let names: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["tool".to_string()], "{names:?}");
}
