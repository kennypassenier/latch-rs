//! M4 (mini-round 2026-09-26): credentials survive a reboot without a
//! backup ritual. Kenny: "Ik wil op een secure plek in het os mijn
//! credentials één keer kunnen opslaan en de rest moet gewoon altijd
//! werken." Measured before deciding: the keyring outlives a reboot on
//! none of his Linux machines (Garuda, the LXCs, WSL — where it does not
//! even outlive a terminal). Decided: every write goes to the encrypted
//! credential file in the latch home, which Syncthing already shares
//! between Garuda and WSL, opened by a machine key beside it.

use latch_core::credentials::{CredStore, Source, CRED_FILE, MACHINE_KEY_FILE};
use latch_core::platform::mock::*;
use latch_core::platform::Platform;

const HOME: &str = "/home/t/.latch";

struct Machine {
    env: MockEnv,
    files: MockFiles,
    keyring: MockKeyring,
    prompt: MockPrompt,
    clock: MockClock,
    proc: MockProc,
}

impl Machine {
    /// A desktop whose keyring is up — the case that used to take writes.
    fn desktop() -> Self {
        Self {
            env: MockEnv::default(),
            files: MockFiles::default(),
            keyring: MockKeyring::default(),
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
            latch_home: HOME.into(),
            // No session cache: every read must open the file on its own,
            // as the first command after a boot does.
            runtime_dir: None,
        }
    }
    fn file(&self, name: &str) -> Option<Vec<u8>> {
        self.files
            .files
            .borrow()
            .get(&format!("{HOME}/{name}"))
            .cloned()
    }
    /// The same disk after a reboot: files kept, keyring and env empty.
    fn rebooted(&self) -> Self {
        let next = Self::desktop();
        for (path, bytes) in self.files.files.borrow().iter() {
            next.files.seed(path, bytes);
        }
        next
    }
}

#[test]
fn a_write_lands_in_the_file_even_when_a_keyring_is_up() {
    let m = Machine::desktop();
    let p = m.platform();
    assert_eq!(
        CredStore::new(&p).set("pat", b"ghp_x").unwrap(),
        Source::File
    );
    assert!(m.keyring.slots.borrow().is_empty(), "keyring took a write");
    assert!(m.file(CRED_FILE).is_some());
}

#[test]
fn a_stored_credential_survives_a_reboot_without_prompt_or_env() {
    let m = Machine::desktop();
    let p = m.platform();
    CredStore::new(&p).set("pat", b"ghp_x").unwrap();
    CredStore::new(&p).set("key:almanac", &[7u8; 32]).unwrap();

    let after = m.rebooted();
    let pa = after.platform();
    let store = CredStore::new(&pa);
    let (pat, src) = store.get("pat").unwrap().expect("PAT after reboot");
    assert_eq!((pat.as_slice(), src), (b"ghp_x".as_slice(), Source::File));
    let (key, _) = store.get("key:almanac").unwrap().expect("key after reboot");
    assert_eq!(key, vec![7u8; 32]);
}

#[test]
fn the_other_os_reads_it_once_the_latch_home_is_synced() {
    // Garuda writes; Syncthing carries ~/.latch (= ~/.secrets/latch) to
    // WSL, which has never seen this credential and has no keyring entry.
    let garuda = Machine::desktop();
    CredStore::new(&garuda.platform())
        .set("pat", b"ghp_shared")
        .unwrap();
    let wsl = Machine::desktop();
    for name in [CRED_FILE, MACHINE_KEY_FILE] {
        wsl.files.seed(
            &format!("{HOME}/{name}"),
            &garuda.file(name).expect("synced file"),
        );
    }
    let (v, _) = CredStore::new(&wsl.platform())
        .get("pat")
        .unwrap()
        .expect("PAT on the other OS");
    assert_eq!(v, b"ghp_shared");
}

#[test]
fn the_machine_key_is_random_and_is_not_the_credential() {
    let a = Machine::desktop();
    let b = Machine::desktop();
    CredStore::new(&a.platform()).set("pat", b"ghp_x").unwrap();
    CredStore::new(&b.platform()).set("pat", b"ghp_x").unwrap();
    let ka = a.file(MACHINE_KEY_FILE).expect("machine key written");
    let kb = b.file(MACHINE_KEY_FILE).unwrap();
    assert_eq!(ka.len(), 64, "32 random bytes as hex");
    assert_ne!(ka, kb, "two machines minted the same key");
    let sealed = a.file(CRED_FILE).unwrap();
    assert!(
        !sealed.windows(5).any(|w| w == b"ghp_x"),
        "the credential sits in the file as plain text"
    );
}

#[test]
fn a_passphrase_file_keeps_its_passphrase() {
    // A file created on purpose with LATCH_PASSPHRASE gets no machine key
    // and still refuses to open without the passphrase.
    let m = Machine::desktop();
    m.env.set("LATCH_PASSPHRASE", "pp");
    CredStore::new(&m.platform()).set("pat", b"ghp_x").unwrap();
    assert!(m.file(MACHINE_KEY_FILE).is_none());

    let after = m.rebooted();
    let err = CredStore::new(&after.platform()).get("pat").unwrap_err();
    assert!(format!("{err}").contains("LATCH_"), "{err}");
}
