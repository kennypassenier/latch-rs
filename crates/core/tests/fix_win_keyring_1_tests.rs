//! fix-win-keyring-1: the Windows build never reached the Windows
//! Credential Manager. `keyring` 3 picks its default store per target
//! feature, and latch enabled only `linux-native`, so on Windows every
//! entry landed in the crate's in-memory mock store. Found on the Windows
//! runtime check (2026-09-26): `latch key restore` printed
//! "✓ 1 credential(s) restored", the very next `latch state` read
//! `PAT : MISSING`, and `cmdkey /list` held no latch entry — while
//! `latch state` kept reporting `keyring : available`.

/// Runs everywhere: the manifest must ask for the native Windows store.
/// This is the guard Linux CI can hold, since only the Windows job can
/// run the round trip below.
#[test]
fn the_manifest_enables_the_windows_credential_store() {
    let manifest = include_str!("../Cargo.toml");
    let windows_section = manifest
        .split("[target.'cfg(windows)'.dependencies]")
        .nth(1)
        .expect("crates/core/Cargo.toml has a cfg(windows) dependency section");
    let keyring_line = windows_section
        .lines()
        .find(|l| l.trim_start().starts_with("keyring"))
        .expect("the cfg(windows) section configures keyring");
    assert!(
        keyring_line.contains("windows-native"),
        "keyring on Windows must enable windows-native: {keyring_line}"
    );
}

/// The round trip itself: a value written through one keyring handle is
/// read back through a fresh one. The mock store fails this, because each
/// mock entry holds its own credential; a real store passes it.
#[cfg(windows)]
#[test]
fn a_stored_slot_is_readable_through_a_fresh_handle() {
    use latch_core::platform::mock::MockEnv;
    use latch_core::platform::real::RealKeyring;
    use latch_core::platform::Keyring;

    let env = MockEnv::default();
    env.set(
        "LATCH_HOME",
        &format!("C:/latch-fix-win-keyring-1-{}", std::process::id()),
    );
    let slot = "fix-win-keyring-1";
    RealKeyring::new(&env).set(slot, b"canary").expect("write");
    let back = RealKeyring::new(&env).get(slot).expect("read");
    let _ = RealKeyring::new(&env).delete(slot);
    assert_eq!(back.as_deref(), Some(&b"canary"[..]));
}
