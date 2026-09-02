//! D16: the OS keyring namespace follows the latch home, so a second
//! latch home is genuinely separate instead of only looking separate.
//! Mini-round 2026-09-02 (queue item M3), after a restore drill under a
//! throwaway `LATCH_HOME` swept the machine's real PAT into a scratch
//! escrow file: `LATCH_HOME` moved the config, the clone and the
//! credential file, but every home read the same keyring drawer.

use latch_core::platform::mock::MockEnv;
use latch_core::platform::real::{keyring_service, RealKeyring};
use latch_core::platform::Keyring;

fn default_home() -> String {
    dirs::home_dir()
        .map(|p| format!("{}/.latch", p.display()))
        .unwrap_or_else(|| "./.latch".into())
}

#[test]
fn the_default_home_keeps_the_plain_service_name() {
    // Nothing anyone already stored may move: the ordinary home must
    // resolve to exactly the name latch has always used.
    let env = MockEnv::default();
    assert_eq!(keyring_service(&env), "latch");

    // Spelling the default out in LATCH_HOME is the same place, so it
    // must not orphan the keys sitting there.
    let spelled = MockEnv::default();
    spelled.set("LATCH_HOME", &default_home());
    assert_eq!(keyring_service(&spelled), "latch");
}

#[test]
fn another_home_gets_its_own_namespace() {
    let env = MockEnv::default();
    env.set("LATCH_HOME", "/tmp/latch-scratch");
    assert_eq!(keyring_service(&env), "latch@/tmp/latch-scratch");
}

/// The isolation itself can only be proven against a REAL keyring, and
/// CI does not always have one. So this test says out loud whether it
/// ran — a silently skipped guarantee is the failure mode this whole
/// mini-round exists to remove.
#[test]
fn two_homes_cannot_read_each_other_s_slots() {
    let a_env = MockEnv::default();
    a_env.set("LATCH_HOME", "/tmp/d16-home-a");
    let b_env = MockEnv::default();
    b_env.set("LATCH_HOME", "/tmp/d16-home-b");
    // Both are scratch namespaces on purpose: this test must never
    // touch the machine's real `latch` drawer.
    let (a, b) = (RealKeyring::new(&a_env), RealKeyring::new(&b_env));
    assert_ne!(a.service(), b.service());
    assert_ne!(a.service(), "latch");

    if !a.available() {
        eprintln!(
            "D16 isolation NOT PROVEN HERE: no usable OS keyring on this machine \
             (the namespace derivation above still ran). Run this test on a \
             desktop session to exercise it."
        );
        return;
    }

    let slot = "d16-isolation-probe";
    a.set(slot, b"only-home-a").unwrap();
    assert_eq!(
        a.get(slot).unwrap().as_deref(),
        Some(&b"only-home-a"[..]),
        "home A reads back its own slot"
    );
    assert_eq!(
        b.get(slot).unwrap(),
        None,
        "home B must not see home A's slot — that is the whole point"
    );

    a.delete(slot).unwrap();
    assert_eq!(a.get(slot).unwrap(), None, "cleaned up after itself");
}
