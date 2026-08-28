//! L4b end-to-end: W12 file groups against the real git binary — pragma
//! subscription, founding commit, fan-out, divergence + resolve, the
//! three join routes, second-machine pull/edit, and run() expansion.

use latch_core::config::Config;
use latch_core::groups;
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
    let tmp = tempdir::TempDir::new("latch-l4b").unwrap();
    let bare = tmp.path().join("origin.git");
    std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "-q"])
        .arg(&bare)
        .status()
        .unwrap();
    let url = format!("file://{}", bare.display());
    (tmp, url)
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn groups_full_lifecycle() {
    let (tmp, origin) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();

    // Two projects on machine A share the 'media' group: alpha holds the
    // founding content, beta subscribes with an empty pragma-only file.
    let alpha = tmp.path().join("work-a/alpha");
    let beta = tmp.path().join("work-a/beta");
    write(
        &alpha.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=abc\nDB=postgres\n",
    );
    write(&beta.join(".env"), "# latch:group=media\n");
    init::run(&pa, &alpha.display().to_string(), None).unwrap();
    init::run(&pa, &beta.display().to_string(), None).unwrap();

    // ── Founding commit: one content member + one subscriber ────────────
    let out = sync::commit(&pa, &alpha.display().to_string(), "dev").unwrap();
    assert_eq!(out.groups.len(), 1);
    assert!(out.groups[0].changed);
    assert_eq!(out.groups[0].members.len(), 2);
    // Fan-out: beta's empty subscriber received the content.
    assert_eq!(
        read(&beta.join(".env")),
        "# latch:group=media\nSHARED_TOKEN=abc\nDB=postgres\n"
    );
    sync::push(&pa, &alpha.display().to_string(), "dev", false).unwrap();

    // The origin stores content ONCE (in _groups) and only ciphertext.
    let probe = tmp.path().join("probe");
    std::process::Command::new("git")
        .args(["clone", "-q", &origin])
        .arg(&probe)
        .status()
        .unwrap();
    for rel in [
        "_groups/dev/media.enc",
        "alpha/dev/.env.enc",
        "beta/dev/.env.enc",
    ] {
        let enc = std::fs::read(probe.join(rel)).unwrap();
        assert!(enc.starts_with(b"LATCH2"), "{rel}");
        let hay = String::from_utf8_lossy(&enc);
        assert!(!hay.contains("SHARED_TOKEN"), "plaintext leaked into {rel}");
    }

    // ── One member edits → commit fans out to the other ─────────────────
    write(
        &beta.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=xyz\nDB=postgres\n",
    );
    let out = sync::commit(&pa, &beta.display().to_string(), "dev").unwrap();
    assert!(out.groups[0].changed);
    assert!(read(&alpha.join(".env")).contains("SHARED_TOKEN=xyz"));
    sync::push(&pa, &beta.display().to_string(), "dev", false).unwrap();

    // Status: members read Clean against the group content.
    let st = sync::status(&pa, &alpha.display().to_string(), "dev").unwrap();
    assert!(
        st.entries.iter().all(|(_, s)| *s == sync::FileState::Clean),
        "{st:?}"
    );

    // ── Divergence: BOTH edited differently = hard error (W12b) ─────────
    write(
        &alpha.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=alpha-wins\nDB=postgres\n",
    );
    write(
        &beta.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=beta-wins\nDB=mysql\n",
    );
    let err = sync::commit(&pa, &alpha.display().to_string(), "dev").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("diverged"), "{msg}");
    assert!(
        msg.contains("alpha/.env") && msg.contains("beta/.env"),
        "{msg}"
    );
    assert!(msg.contains("SHARED_TOKEN") && msg.contains("DB"), "{msg}");
    assert!(
        msg.contains("group resolve"),
        "remedy must name the fix: {msg}"
    );

    // The only path forward is explicit: resolve --source.
    let rep = groups::resolve(&pa, &alpha.display().to_string(), "dev", "media", ".env").unwrap();
    assert!(rep.changed);
    assert!(read(&beta.join(".env")).contains("SHARED_TOKEN=alpha-wins"));
    sync::push(&pa, &alpha.display().to_string(), "dev", false).unwrap();

    // ── W12c: a NEW member with foreign content must not silently win ───
    let gamma = tmp.path().join("work-a/gamma");
    write(
        &gamma.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=gamma-rogue\n",
    );
    init::run(&pa, &gamma.display().to_string(), None).unwrap();
    let err = sync::commit(&pa, &gamma.display().to_string(), "dev").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("gamma/.env"), "{msg}");
    assert!(
        msg.contains("group adopt"),
        "both intents in the remedy: {msg}"
    );

    // Route 1: empty the file → subscribes and receives the content.
    write(&gamma.join(".env"), "# latch:group=media\n");
    sync::commit(&pa, &gamma.display().to_string(), "dev").unwrap();
    assert!(read(&gamma.join(".env")).contains("SHARED_TOKEN=alpha-wins"));
    sync::push(&pa, &gamma.display().to_string(), "dev", false).unwrap();

    // Route 3: adopt — a new member's content BECOMES the group content.
    let delta = tmp.path().join("work-a/delta");
    write(
        &delta.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=delta-standard\nDB=postgres\n",
    );
    init::run(&pa, &delta.display().to_string(), None).unwrap();
    assert!(sync::commit(&pa, &delta.display().to_string(), "dev").is_err());
    groups::resolve(&pa, &delta.display().to_string(), "dev", "media", ".env").unwrap();
    for proj in [&alpha, &beta, &gamma, &delta] {
        assert!(
            read(&proj.join(".env")).contains("SHARED_TOKEN=delta-standard"),
            "{proj:?}"
        );
    }
    sync::push(&pa, &delta.display().to_string(), "dev", false).unwrap();

    // ── group list: every member visible, key held ──────────────────────
    let infos = groups::list(&pa, "dev").unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].name, "media");
    assert_eq!(infos[0].members.len(), 4);
    assert!(infos[0].has_content && infos[0].key_held);

    // ── verify covers the group envelope too (S6) ───────────────────────
    let ver = consume::verify(&pa, None).unwrap();
    let group_entry = ver
        .entries
        .iter()
        .find(|(rel, _)| rel == "_groups/dev/media.enc")
        .expect("group envelope is verified");
    assert!(matches!(group_entry.1, consume::VerifyState::Ok));

    // ── Machine B: pull materializes members, edit round-trips ──────────
    let store_a = latch_core::credentials::CredStore::new(&pa);
    let (alpha_key, _) = store_a.get("key:alpha").unwrap().unwrap();
    let (group_key, _) = store_a.get("group:media.dev").unwrap().unwrap();

    let alpha_b = tmp.path().join("work-b/alpha");
    std::fs::create_dir_all(&alpha_b).unwrap();
    let b = Machine::new(tmp.path(), "home-b", &origin);
    b.env.set("LATCH_KEY_ALPHA", &hex::encode(&alpha_key));
    b.env.set("LATCH_GROUP_MEDIA_DEV", &hex::encode(&group_key));
    let pb = b.platform();
    init::run(&pb, &alpha_b.display().to_string(), Some("alpha".into())).unwrap();

    let pulled = sync::pull(&pb, &alpha_b.display().to_string(), "dev", false, false).unwrap();
    assert_eq!(pulled.written, vec![".env"]);
    assert_eq!(
        read(&alpha_b.join(".env")),
        "# latch:group=media\nSHARED_TOKEN=delta-standard\nDB=postgres\n",
        "stub expanded to pragma + group content"
    );

    // run(): the child sees the GROUP's variables (stub → content).
    let out_file = tmp.path().join("run-out.txt");
    let cmd = format!("printf '%s' \"$SHARED_TOKEN\" > {}", out_file.display());
    let run = consume::run(
        &pb,
        &alpha_b.display().to_string(),
        "dev",
        "sh",
        &["-c", &cmd],
        false,
    )
    .unwrap();
    assert_eq!(run.exit_code, 0);
    assert_eq!(read(&out_file), "delta-standard");

    // Edit on B and commit: pull registered B's baseline, so this is a
    // KNOWN member's change (W12b candidate), not a foreign join (W12c).
    write(
        &alpha_b.join(".env"),
        "# latch:group=media\nSHARED_TOKEN=from-b\nDB=postgres\n",
    );
    let out = sync::commit(&pb, &alpha_b.display().to_string(), "dev").unwrap();
    assert!(out.groups[0].changed, "B's edit adopted as group content");
    sync::push(&pb, &alpha_b.display().to_string(), "dev", false).unwrap();

    // Back on A: pull takes B's version into every member.
    let pulled = sync::pull(&pa, &alpha.display().to_string(), "dev", false, true).unwrap();
    assert!(!pulled.written.is_empty());
    assert!(read(&alpha.join(".env")).contains("SHARED_TOKEN=from-b"));
}

#[test]
fn all_empty_group_is_an_error() {
    let (tmp, origin) = scratch();
    let a = Machine::new(tmp.path(), "home-a", &origin);
    let pa = a.platform();
    let proj = tmp.path().join("work-a/solo");
    write(&proj.join(".env"), "# latch:group=ghost\n");
    init::run(&pa, &proj.display().to_string(), None).unwrap();
    let err = sync::commit(&pa, &proj.display().to_string(), "dev").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("ghost") && msg.contains("empty"), "{msg}");
}
