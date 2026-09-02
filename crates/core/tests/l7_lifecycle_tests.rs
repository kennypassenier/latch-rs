//! L7: M5 self-update state machine (scripted release), D5 project
//! bind/unbind against real git, M4 path resolution.

use latch_core::config::Config;
use latch_core::ops::{init, project, sync, update};
use latch_core::platform::mock::{
    MockClock, MockEnv, MockFiles, MockKeyring, MockProc, MockPrompt,
};
use latch_core::platform::real::{RealFiles, RealProc};
use latch_core::platform::Platform;

// ── M5 · self-update ────────────────────────────────────────────────────

struct UpdateRig {
    env: MockEnv,
    files: MockFiles,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
    proc: MockProc,
}

impl UpdateRig {
    fn new() -> Self {
        Self {
            env: MockEnv::default(),
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
    /// Script a full fake release: metadata, signed sums, binary, probe.
    /// `sig` is the exact SHA256SUMS.minisig content for the sums string
    /// (the sums are `<sum_hex>  <asset>\n`). The ".minisig" response is
    /// registered FIRST so the substring matcher doesn't hand a
    /// SHA256SUMS.minisig request the plain sums.
    fn script_release(
        &self,
        tag: &str,
        binary: &[u8],
        sum_hex: &str,
        sig: &str,
        probe: (i32, &str),
    ) {
        self.proc.respond(
            "releases/latest",
            0,
            format!(r#"{{"tag_name": "{}", "assets": []}}"#, tag).as_bytes(),
            b"",
        );
        self.proc
            .respond("SHA256SUMS.minisig", 0, sig.as_bytes(), b"");
        self.proc.respond(
            "SHA256SUMS",
            0,
            format!("{}  {}\n", sum_hex, update::ASSET_LINUX).as_bytes(),
            b"",
        );
        self.proc
            .respond("latch-x86_64-unknown-linux-gnu", 0, binary, b"");
        self.proc
            .respond("--version", probe.0, probe.1.as_bytes(), b"");
    }
}

// D4 test vector: a throwaway minisign key (generated with rsign; NOT the
// production key) and signatures over the exact SHA256SUMS strings each
// test uses. This exercises the signature gate end-to-end without the
// real signing key.
const TEST_PUBKEY: &str = "RWS0gFj3LpbipVHPdSnQfFp0NI/kv/0CoaHLd765/TH6TQS8sefm9GEZ";
const SIG_NEW: &str = "untrusted comment: signature from rsign secret key\nRUS0gFj3Lpbipf6JkvgitGKJpAQOJki1X9iBX7PSia9ZNTCP9zD4urKYS8Frx87Sha1R5d7p0X/3z1nnYQh42V+nliJIqGlFsAA=\ntrusted comment: timestamp:1786509498\tfile:S_NEW-BINARY-9.9.9\tprehashed\n4oHUaagnAgvwioY/2x2F3shZqVq3DYshaHnQAwSMjCiPzJe9ezy54EFuo6dlzfDrnQIHkuQj7OIAe4LdR6I5BQ==\n";
const SIG_REALRELEASE: &str = "untrusted comment: signature from rsign secret key\nRUS0gFj3LpbipQxW8n0S7YEcHVlKSm/req5KMZjtOvY1bE6kt7BeGRfgVQci7+Sr8kqXtxWcp07b8D6na/w7Afh0F/5cNN/mEQs=\ntrusted comment: timestamp:1786509498\tfile:S_the-real-release\tprehashed\nxg7Lri5HJvTzd1Yit8MSS9coZiy2G9RjjtmjHX0AUIk2JM2WN/7TRvrflEgZ33HupCZfyN/5q/gGi+NmFhAYDw==\n";
const SIG_BROKEN: &str = "untrusted comment: signature from rsign secret key\nRUS0gFj3LpbipTVZVCLzL4AUWnPIp5pe3t++XpC5Uwa7fmRHsnrdH/xrptMEErA3nBxg5UlDA2Y+hF8yFSJ/A5aZKVmZ1GrlcwE=\ntrusted comment: timestamp:1786509499\tfile:S_BROKEN-BINARY\tprehashed\n2bBklNHOsXKPrGC0qusMzXHpsKNJBSsZ21coHiJ1v7BMNBe4u3IJ3+nmhHLVZd8QNPQOQW+730l3PKI8zlspDw==\n";

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

#[test]
fn update_happy_path_keeps_previous_binary() {
    let rig = UpdateRig::new();
    let old = b"OLD-BINARY".to_vec();
    let new = b"NEW-BINARY-9.9.9".to_vec();
    rig.files.seed("/usr/local/bin/latch", &old);
    rig.script_release(
        "v9.9.9",
        &new,
        &sha256_hex(&new),
        SIG_NEW,
        (0, "latch 9.9.9"),
    );

    let p = rig.platform();
    let out = update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap();
    assert_eq!(
        out,
        update::UpdateOutcome::Updated {
            from: "2.0.0".into(),
            to: "9.9.9".into(),
            previous: "/usr/local/bin/latch.prev".into()
        }
    );
    assert_eq!(p.files.read("/usr/local/bin/latch").unwrap().unwrap(), new);
    assert_eq!(
        p.files.read("/usr/local/bin/latch.prev").unwrap().unwrap(),
        old,
        "the previous binary is kept"
    );
    assert!(
        p.files
            .read("/home/t/.latch/update-staging")
            .unwrap()
            .is_none(),
        "staging cleaned up"
    );
}

#[test]
fn update_aborts_on_checksum_mismatch() {
    let rig = UpdateRig::new();
    let old = b"OLD-BINARY".to_vec();
    let new = b"TAMPERED".to_vec();
    rig.files.seed("/usr/local/bin/latch", &old);
    // Manifest says a DIFFERENT sum than the download hashes to.
    rig.script_release(
        "v9.9.9",
        &new,
        &sha256_hex(b"the-real-release"),
        SIG_REALRELEASE,
        (0, "x"),
    );

    let p = rig.platform();
    let err =
        update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap_err();
    assert!(format!("{err}").contains("checksum"), "{err}");
    assert_eq!(
        p.files.read("/usr/local/bin/latch").unwrap().unwrap(),
        old,
        "install untouched after checksum abort"
    );
    assert!(p.files.read("/usr/local/bin/latch.prev").unwrap().is_none());
}

#[test]
fn update_aborts_when_new_binary_does_not_run() {
    let rig = UpdateRig::new();
    let old = b"OLD-BINARY".to_vec();
    let new = b"BROKEN-BINARY".to_vec();
    rig.files.seed("/usr/local/bin/latch", &old);
    // Correct checksum but the probe fails to execute.
    rig.script_release("v9.9.9", &new, &sha256_hex(&new), SIG_BROKEN, (127, ""));

    let p = rig.platform();
    let err =
        update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap_err();
    assert!(format!("{err}").contains("does not run"), "{err}");
    assert_eq!(
        p.files.read("/usr/local/bin/latch").unwrap().unwrap(),
        old,
        "old binary intact after a non-executing update"
    );
    assert!(
        p.files
            .read("/home/t/.latch/update-staging")
            .unwrap()
            .is_none(),
        "staging removed on abort"
    );
}

#[test]
fn update_reports_up_to_date() {
    let rig = UpdateRig::new();
    rig.proc
        .respond("releases/latest", 0, br#"{"tag_name": "v2.0.0"}"#, b"");
    let p = rig.platform();
    let out = update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap();
    assert_eq!(
        out,
        update::UpdateOutcome::UpToDate {
            version: "2.0.0".into()
        }
    );
    assert!(
        rig.proc.calls_containing("SHA256SUMS").is_empty(),
        "no downloads"
    );
}

// D4 · a valid-format signature that does NOT match the sums is rejected
// before any binary is trusted.
#[test]
fn d4_wrong_signature_is_refused() {
    let rig = UpdateRig::new();
    rig.files.seed("/usr/local/bin/latch", b"OLD");
    // Sums for NEW-BINARY, but paired with the signature over a DIFFERENT
    // sums string (SIG_BROKEN) → signature won't verify.
    rig.script_release(
        "v9.9.9",
        b"NEW-BINARY-9.9.9",
        &sha256_hex(b"NEW-BINARY-9.9.9"),
        SIG_BROKEN,
        (0, "latch 9.9.9"),
    );
    let p = rig.platform();
    let err =
        update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap_err();
    assert!(format!("{err}").contains("does NOT verify"), "{err}");
    assert_eq!(
        p.files.read("/usr/local/bin/latch").unwrap().unwrap(),
        b"OLD",
        "nothing changed after a bad signature"
    );
}

// D4 · a build whose RELEASE_PUBKEY is still the placeholder fails closed
// (refuses every release) rather than trusting an unsigned manifest.
#[test]
fn d4_placeholder_key_fails_closed() {
    let rig = UpdateRig::new();
    rig.files.seed("/usr/local/bin/latch", b"OLD");
    rig.script_release(
        "v9.9.9",
        b"NEW-BINARY-9.9.9",
        &sha256_hex(b"NEW-BINARY-9.9.9"),
        SIG_NEW,
        (0, "latch 9.9.9"),
    );
    let p = rig.platform();
    // The real entry point uses the baked-in (placeholder) key.
    let err = update::run(&p, "2.0.0", "/usr/local/bin/latch").unwrap_err();
    assert!(
        format!("{err}").contains("no valid release-signing key")
            || format!("{err}").contains("does NOT verify"),
        "{err}"
    );
    assert_eq!(
        p.files.read("/usr/local/bin/latch").unwrap().unwrap(),
        b"OLD"
    );
}

// D4 · downgrade guard: a `latest` moved back to an older version does
// not "update" us down.
#[test]
fn d4_downgrade_is_refused() {
    let rig = UpdateRig::new();
    rig.proc
        .respond("releases/latest", 0, br#"{"tag_name": "v1.0.0"}"#, b"");
    let p = rig.platform();
    let out = update::run_with_pubkey(&p, "2.0.0", "/usr/local/bin/latch", TEST_PUBKEY).unwrap();
    assert_eq!(
        out,
        update::UpdateOutcome::UpToDate {
            version: "2.0.0".into()
        },
        "an older latest tag must not downgrade us"
    );
}

// ── M4 · path resolution ────────────────────────────────────────────────

#[test]
fn path_honors_config_override_and_checks_path_env() {
    let rig = UpdateRig::new();
    rig.env.set("PATH", "/usr/bin:/opt/tools");
    let p = rig.platform();

    // No override: the running exe's own path.
    let r = project::path_report(&p, "/somewhere/latch").unwrap();
    assert_eq!(r.install_path, "/somewhere/latch");
    assert!(!r.on_path);

    // Config override wins (M4 auto-test requirement).
    let mut cfg = Config::load(&p).unwrap();
    cfg.install_dir = Some("/opt/tools".into());
    cfg.save(&p).unwrap();
    let r = project::path_report(&p, "/somewhere/latch").unwrap();
    assert_eq!(r.install_path, "/opt/tools/latch");
    assert!(r.on_path, "override dir is on the scripted PATH");
}

// ── D5 · project bind/unbind against real git ───────────────────────────

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

#[test]
fn bind_links_existing_project_and_pull_works_there() {
    let tmp = tempdir::TempDir::new("latch-l7").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let origin = format!("file://{}", bare.display());

    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let dir1 = tmp.path().join("work/first");
    std::fs::create_dir_all(&dir1).unwrap();
    std::fs::write(dir1.join(".env"), "X=1\n").unwrap();
    init::run(&pa, &dir1.display().to_string(), Some("solo".into())).unwrap();
    sync::commit(&pa, &dir1.display().to_string(), "dev").unwrap();
    sync::push(&pa, &dir1.display().to_string(), "dev", false, true).unwrap();

    // Unknown name refuses (bind never creates).
    let err = project::bind(&pa, "nope", "/tmp/x").unwrap_err();
    assert!(format!("{err}").contains("not a known project"), "{err}");

    // Re-bind to a FRESH directory → pull materializes there (D5 auto).
    let dir2 = tmp.path().join("work/second");
    std::fs::create_dir_all(&dir2).unwrap();
    project::bind(&pa, "solo", &dir2.display().to_string()).unwrap();
    let pulled = sync::pull(&pa, &dir2.display().to_string(), "dev", false, false).unwrap();
    assert_eq!(pulled.written, vec![".env"]);
    assert_eq!(std::fs::read_to_string(dir2.join(".env")).unwrap(), "X=1\n");

    // Unbind forgets the link; keys stay.
    project::unbind(&pa, "solo").unwrap();
    assert!(project::list(&pa).unwrap().is_empty());
    let store = latch_core::credentials::CredStore::new(&pa);
    assert!(
        store.get("key:solo").unwrap().is_some(),
        "keys survive unbind"
    );
    let err = project::unbind(&pa, "solo").unwrap_err();
    assert!(format!("{err}").contains("not linked"), "{err}");
}
