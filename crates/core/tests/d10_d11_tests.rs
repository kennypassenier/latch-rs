//! D10 (`latch cat`: one file decrypted to memory, raw or --expand) and
//! D11 (`latch run` merge rules: same name + same value merges silently,
//! different values are a hard error naming both files, --last-wins opts
//! back into the old behaviour). E2E against real git; chosen designs
//! from the 2026-08-28 mini-round (three deep-dive rounds on D11).

use latch_core::config::Config;
use latch_core::ops::{consume, init, sync};
use latch_core::platform::mock::{MockClock, MockEnv, MockKeyring, MockPrompt};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Platform;

struct Machine {
    home: String,
    env: MockEnv,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
}

impl Machine {
    fn new(base: &std::path::Path, name: &str, origin: &str) -> Self {
        let home = base.join(name).display().to_string();
        let env = MockEnv::default();
        env.set("LATCH_PASSPHRASE", "test-pp");
        let m = Self {
            home,
            env,
            keyring: MockKeyring::headless(),
            prompt: MockPrompt::default(),
            clock: MockClock::default(),
        };
        let p = m.platform();
        let mut cfg = Config::load(&p).unwrap();
        cfg.repo = Some(origin.to_string());
        cfg.save(&p).unwrap();
        m
    }
    fn platform(&self) -> Platform<'_> {
        static FILES: RealFiles = RealFiles;
        static PROC: RealProc = RealProc;
        Platform {
            env: &self.env,
            files: &FILES,
            keyring: &self.keyring,
            prompt: &self.prompt,
            clock: &self.clock,
            proc: &PROC,
            latch_home: self.home.clone(),
            runtime_dir: None,
        }
    }
}

fn scratch() -> (tempdir::TempDir, String) {
    let tmp = tempdir::TempDir::new("latch-d10").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    (tmp, format!("file://{}", bare.display()))
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// Every file under `dir`, read as bytes — the plaintext-scan helper.
fn scan_tree(dir: &std::path::Path, needle: &[u8], hits: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                scan_tree(&path, needle, hits);
            } else if let Ok(bytes) = std::fs::read(&path) {
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    hits.push(path.display().to_string());
                }
            }
        }
    }
}

/// The multi-app shape: two apps, a shared duplicate (same value) and a
/// template chain crossing files.
fn seed(tmp: &tempdir::TempDir, origin: &str) -> (Machine, String) {
    let a = Machine::new(tmp.path(), "home", origin);
    let pa = a.platform();
    let proj = tmp.path().join("work/stacks");
    write(
        &proj.join("web/.env"),
        "# web app\n\nTOKEN=\"web-secret\"\nSHARED_URL=http://loki:3100\nAPI=${BASE}/v1\n",
    );
    write(
        &proj.join("worker/.env"),
        "BASE=http://api.internal\nSHARED_URL=http://loki:3100\n",
    );
    init::run(&pa, &proj.display().to_string(), Some("stacks".into())).unwrap();
    sync::commit(&pa, &proj.display().to_string(), "dev").unwrap();
    sync::push(&pa, &proj.display().to_string(), "dev", false, true).unwrap();
    (a, proj.display().to_string())
}

#[test]
fn cat_raw_is_byte_identical_and_zero_disk() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();

    let original = std::fs::read(std::path::Path::new(&proj).join("web/.env")).unwrap();
    let out = consume::cat(&pa, &proj, "dev", "web/.env", false, false).unwrap();
    assert_eq!(
        out.content, original,
        "raw cat is byte-identical to the committed file"
    );

    // D10 plaintext-scan: nothing under latch home (clone included) holds
    // the secret in the clear — cat decrypts to memory only.
    let mut hits = Vec::new();
    scan_tree(std::path::Path::new(&a.home), b"web-secret", &mut hits);
    assert!(hits.is_empty(), "plaintext on disk: {:?}", hits);

    // Missing file and unknown env are hard errors with a remedy (M7).
    let err = consume::cat(&pa, &proj, "dev", "nope/.env", false, false).unwrap_err();
    assert!(format!("{err}").contains("no file"), "{err}");

    // A path abusing the reserved separator is refused, not resolved.
    let err = consume::cat(&pa, &proj, "dev", "a__b/.env", false, false).unwrap_err();
    assert!(format!("{err}").contains("__"), "{err}");
}

#[test]
fn cat_expand_resolves_across_files_strictly() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();

    // ${BASE} lives in worker/.env; web/.env's API line must resolve
    // through the project-wide map. Quotes are normalized like run does.
    let out = consume::cat(&pa, &proj, "dev", "web/.env", true, false).unwrap();
    let text = String::from_utf8(out.content).unwrap();
    assert!(text.contains("API=http://api.internal/v1"), "{text}");
    assert!(text.contains("TOKEN=web-secret"), "{text}");
    assert!(text.contains("# web app\n"), "comments survive expansion");

    // Strict: a reference to a variable that exists nowhere is an error.
    let proj_path = std::path::Path::new(&proj);
    write(&proj_path.join("web/.env"), "API=${NOWHERE}/v1\n");
    sync::commit(&pa, &proj, "dev").unwrap();
    sync::push(&pa, &proj, "dev", false, true).unwrap();
    let err = consume::cat(&pa, &proj, "dev", "web/.env", true, false).unwrap_err();
    assert!(format!("{err}").contains("NOWHERE"), "{err}");
}

#[test]
fn run_merges_same_values_and_errors_on_different_ones() {
    let (tmp, origin) = scratch();
    let (a, proj) = seed(&tmp, &origin);
    let pa = a.platform();

    // SHARED_URL appears in both files with the SAME value: no error,
    // nothing lost (the LOKI_URL shape from Kenny's real repo).
    let out = consume::run(
        &pa,
        &proj,
        "dev",
        "sh",
        &["-c", "test \"$SHARED_URL\" = http://loki:3100"],
        false,
    )
    .unwrap();
    assert_eq!(out.exit_code, 0, "same-value duplicate merges silently");

    // Now let the values diverge: hard error naming BOTH files (D11).
    let proj_path = std::path::Path::new(&proj);
    write(
        &proj_path.join("worker/.env"),
        "BASE=http://api.internal\nSHARED_URL=http://other:3100\n",
    );
    sync::commit(&pa, &proj, "dev").unwrap();
    sync::push(&pa, &proj, "dev", false, true).unwrap();
    let err = consume::run(&pa, &proj, "dev", "true", &[], false).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("SHARED_URL"), "{msg}");
    assert!(msg.contains("web/.env"), "{msg}");
    assert!(msg.contains("worker/.env"), "{msg}");
    assert!(
        msg.contains("--last-wins"),
        "remedy names the escape: {msg}"
    );

    // --last-wins accepts it: the alphabetically last file's value wins.
    let out = consume::run(
        &pa,
        &proj,
        "dev",
        "sh",
        &["-c", "test \"$SHARED_URL\" = http://other:3100"],
        true,
    )
    .unwrap();
    assert_eq!(out.exit_code, 0, "worker/.env sorts after web/.env");

    // cat --expand hits the same merge, so the same conflict errors too;
    // raw cat cannot collide by construction and stays fine.
    let err = consume::cat(&pa, &proj, "dev", "web/.env", true, false).unwrap_err();
    assert!(format!("{err}").contains("SHARED_URL"), "{err}");
    consume::cat(&pa, &proj, "dev", "web/.env", false, false).unwrap();
}
