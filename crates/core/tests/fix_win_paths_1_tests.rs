//! fix-win-paths-1: three places treated an OS path as if `/` were the
//! only separator. Found on the Windows runtime check (2026-09-26) with the
//! v2.5.0 release binary:
//! - `latch init` in `...\latch-wincheck\work\wincheck` refused with
//!   "'c:\users\kenny\...\wincheck' is not a valid project name";
//! - `latch path` suggested `export PATH=".:$PATH"`;
//! - a `.env` in a subdirectory was silently left out of `latch status`
//!   and `latch commit`, because discovery saw `sub\.env` and matched the
//!   file name against the whole string.
//!
//! Repository paths stay `/`-separated everywhere; only paths that come
//! from the operating system needed fixing.

use latch_core::ops::{init, project};
use latch_core::platform::mock::*;
use latch_core::platform::real::RealFiles;
use latch_core::platform::{Files, Platform};

struct World {
    env: MockEnv,
    files: MockFiles,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
    proc: MockProc,
}

impl World {
    fn new() -> Self {
        let env = MockEnv::default();
        env.set("LATCH_PASSPHRASE", "pp");
        Self {
            env,
            files: MockFiles::default(),
            keyring: MockKeyring::headless(),
            prompt: MockPrompt::non_interactive(),
            clock: MockClock::default(),
            proc: MockProc::default(),
        }
    }
    fn platform(&self) -> Platform<'_> {
        Platform {
            env: &self.env,
            files: &self.files,
            keyring: &self.keyring,
            prompt: &self.prompt,
            clock: &self.clock,
            proc: &self.proc,
            latch_home: "/home/t/.latch".into(),
            runtime_dir: None,
        }
    }
}

#[test]
fn init_names_a_windows_directory_by_its_last_component() {
    let w = World::new();
    let p = w.platform();
    let out = init::run(&p, r"C:\Users\Kenny\work\My_App", None).unwrap();
    assert_eq!(out.project, "my-app");
}

#[test]
fn path_report_finds_the_directory_of_a_windows_exe() {
    let w = World::new();
    let p = w.platform();
    let r = project::path_report(&p, r"C:\tools\latch.exe").unwrap();
    assert_eq!(r.install_path, r"C:\tools\latch.exe");
    assert!(
        r.remedy.contains(r"C:\tools"),
        "remedy names the exe's directory: {}",
        r.remedy
    );
}

#[test]
fn walk_reports_nested_files_with_forward_slashes() {
    let tmp = tempdir::TempDir::new("latch-fix-win-paths-1").unwrap();
    std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub").join(".env"), "A=1\n").unwrap();
    std::fs::write(tmp.path().join(".env"), "B=2\n").unwrap();
    let root = tmp.path().display().to_string();
    let walked = RealFiles.walk(&root).unwrap();
    assert!(walked.contains(&"sub/.env".to_string()), "{walked:?}");
}

#[cfg(windows)]
#[test]
fn path_report_reads_a_windows_path_list() {
    let w = World::new();
    w.env.set("PATH", r"C:\Windows;C:\Tools");
    let p = w.platform();
    let r = project::path_report(&p, r"C:\tools\latch.exe").unwrap();
    assert!(
        r.on_path,
        "PATH entries compare case-insensitively on Windows"
    );
    assert!(!r.remedy.contains("export"), "{}", r.remedy);
}
