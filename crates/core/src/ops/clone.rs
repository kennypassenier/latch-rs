//! M2 machine clone (AR5): E2E-encrypted credential transfer. The
//! offer/payload dance is X25519 ECDH — the payload is sealed for exactly
//! one offer, safe to travel over anything (ssh, chat, a QR code). The
//! `--to <ssh>` wrapper runs the whole dance in one command; the manual
//! offer/create/apply verbs remain for air-gapped bootstrap.
//!
//! Verify code: both ends derive a 6-digit code from the two public keys.
//! Apply refuses without the matching code (or an interactive confirm) —
//! that is the MITM check, and M7 makes it a hard error headless.

use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::credentials::CredStore;
use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::platform::Platform;

const OFFER_PREFIX: &str = "LATCH-OFFER:";
const PAYLOAD_PREFIX: &str = "LATCH-CLONE:";
const OFFER_FILE: &str = "clone-offer.key";
const OFFER_TTL_SECS: u64 = 15 * 60;
const CLONE_LABEL: &str = "latch-clone";

fn transport_key(shared: &[u8], offer_pub: &[u8; 32], source_pub: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut h = sha2::Sha256::new();
    h.update(b"latch-clone-key-v1");
    h.update(shared);
    h.update(offer_pub);
    h.update(source_pub);
    h.finalize().into()
}

/// Constant-time byte comparison (D5): the verify code is low-entropy,
/// so its check must not leak position information through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Reject an ssh target that could be read as an option (D5): ssh has no
/// `--` end-of-options, so a target like `-oProxyCommand=…` becomes a
/// command-executing flag.
fn validate_ssh_target(target: &str) -> Result<(), LatchError> {
    if target.is_empty()
        || target.starts_with('-')
        || target.contains(['\n', '\r', '\0', ' '])
    {
        return Err(LatchError::other(
            format!("refusing ssh target '{}'", target),
            "use a plain user@host (no leading '-', no spaces) — ssh treats a leading dash as an option",
        ));
    }
    Ok(())
}

/// The 6-digit verify code both sides display — derived from the two
/// PUBLIC keys, so a man-in-the-middle changes it on one side.
pub fn verify_code(offer_pub: &[u8; 32], source_pub: &[u8; 32]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"latch-clone-code-v1");
    h.update(offer_pub);
    h.update(source_pub);
    let d: [u8; 32] = h.finalize().into();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{:06}", n)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ClonePayload {
    repo: Option<String>,
    slots: std::collections::BTreeMap<String, String>,
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], LatchError> {
    let raw = hex::decode(s).map_err(|_| LatchError::Format {
        context: what.into(),
        detail: "not valid hex".into(),
    })?;
    raw.try_into().map_err(|_| LatchError::Format {
        context: what.into(),
        detail: "wrong length (expected 32 bytes)".into(),
    })
}

// ── Target side: offer ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct OfferOutcome {
    pub offer: String,
}

/// K1: remove an abandoned offer secret whose TTL has elapsed. An offer
/// that is never answered would otherwise leave its X25519 secret in
/// ~/.latch indefinitely; callers (state/doctor, a new offer) sweep it.
pub fn cleanup_expired_offer(p: &Platform) -> Result<bool, LatchError> {
    let offer_path = format!("{}/{}", p.latch_home, OFFER_FILE);
    if let Some(mtime) = p.files.mtime_unix(&offer_path)? {
        if p.clock.now_unix().saturating_sub(mtime) > OFFER_TTL_SECS {
            p.files.remove(&offer_path)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Generate a fresh offer on the RECEIVING machine. The secret half waits
/// (0600, 15-minute TTL) for `latch clone apply`; the printed offer
/// string travels to the source machine.
pub fn offer(p: &Platform) -> Result<OfferOutcome, LatchError> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    p.files
        .write_atomic(&format!("{}/{}", p.latch_home, OFFER_FILE), &seed)?;
    Ok(OfferOutcome {
        offer: format!("{}{}", OFFER_PREFIX, hex::encode(public.as_bytes())),
    })
}

// ── Source side: create ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct CreateOutcome {
    pub payload: String,
    pub code: String,
    pub slots: Vec<String>,
}

/// Build the sealed payload for an offer, scoped (M2): whole setup by
/// default, one project with `--project`, one environment of it with
/// `--env` on top.
pub fn create(
    p: &Platform,
    offer_str: &str,
    project: Option<&str>,
    env: Option<&str>,
) -> Result<CreateOutcome, LatchError> {
    let offer_hex =
        offer_str
            .trim()
            .strip_prefix(OFFER_PREFIX)
            .ok_or_else(|| LatchError::Format {
                context: "clone offer".into(),
                detail: format!("expected a string starting with {}", OFFER_PREFIX),
            })?;
    let offer_pub_bytes = parse_hex32(offer_hex, "clone offer")?;
    let offer_pub = PublicKey::from(offer_pub_bytes);

    if env.is_some() && project.is_none() {
        return Err(LatchError::other(
            "--env needs --project",
            "an environment scope is always inside a project scope",
        ));
    }

    let store = CredStore::new(p);
    let all = super::keyops::enumerate_slots(p, &store)?;
    let selected: Vec<String> = match project {
        None => all,
        Some(proj) => {
            let mut keep: Vec<String> = all
                .iter()
                .filter(|slot| {
                    if *slot == "pat" {
                        return true; // the target must reach the repo
                    }
                    if let Some(label) = slot.strip_prefix("key:") {
                        let matches_project =
                            label == proj || label.starts_with(&format!("{}.", proj));
                        let matches_env = match env {
                            Some(e) => {
                                label == proj || label == crate::keys::label_for(proj, Some(e))
                            }
                            None => true,
                        };
                        return matches_project && matches_env;
                    }
                    false
                })
                .cloned()
                .collect();
            // W12: group keys referenced by this project's members travel
            // with it — a member without its group key is unusable.
            keep.extend(project_group_slots(p, proj, env)?);
            keep.sort();
            keep.dedup();
            keep
        }
    };
    if selected.is_empty() {
        return Err(LatchError::other(
            "the selected scope contains no credentials",
            "check --project/--env spelling (latch state lists projects)",
        ));
    }

    let mut payload = ClonePayload {
        repo: Config::load(p)?.repo,
        slots: Default::default(),
    };
    for slot in &selected {
        if let Some((raw, _)) = store.get(slot)? {
            payload.slots.insert(slot.clone(), hex::encode(raw));
        }
    }
    let plain = serde_json::to_vec(&payload).expect("payload serializes");

    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let eph = StaticSecret::from(seed);
    let source_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&offer_pub);
    let key = transport_key(shared.as_bytes(), &offer_pub_bytes, source_pub.as_bytes());
    let sealed = envelope::seal(&key, &KeyId::new(CLONE_LABEL, 1)?, &plain)?;

    Ok(CreateOutcome {
        payload: format!(
            "{}{}:{}",
            PAYLOAD_PREFIX,
            hex::encode(source_pub.as_bytes()),
            hex::encode(&sealed)
        ),
        code: verify_code(&offer_pub_bytes, source_pub.as_bytes()),
        slots: selected,
    })
}

/// Group keys used by `project`'s members (optionally one env): found by
/// decrypting the project's stubs and reading their pragmas.
fn project_group_slots(
    p: &Platform,
    project: &str,
    env: Option<&str>,
) -> Result<Vec<String>, LatchError> {
    let store = CredStore::new(p);
    let mut out = Vec::new();
    let Ok(repo) = super::consume::repo_handle(p) else {
        return Ok(out);
    };
    if repo.ensure().is_err() {
        return Ok(out);
    }
    for rel in repo.list(project)? {
        let Some((e, _file)) = rel.split_once('/') else {
            continue;
        };
        if env.is_some_and(|want| want != e) || !rel.ends_with(".enc") {
            continue;
        }
        let Some(key) = crate::keys::for_env(&store, project, e)? else {
            continue;
        };
        let full_rel = format!("{}/{}", project, rel);
        let Some(sealed) = repo.read(&full_rel)? else {
            continue;
        };
        let Ok(plain) = envelope::open(&key.key, &key.id, &sealed, &full_rel) else {
            continue;
        };
        if let Some((name, _)) = crate::groups::parse_member(&plain) {
            out.push(format!("group:{}.{}", name, e));
        }
    }
    Ok(out)
}

// ── Target side: apply ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct ApplyOutcome {
    pub applied: Vec<String>,
    pub repo_configured: bool,
}

/// Open a payload against the pending offer and install its credentials.
/// The verify code MUST match: pass `--code` (required headless per M7)
/// or confirm interactively against the code the source machine shows.
pub fn apply(
    p: &Platform,
    payload_str: &str,
    code: Option<&str>,
) -> Result<ApplyOutcome, LatchError> {
    let offer_path = format!("{}/{}", p.latch_home, OFFER_FILE);
    let Some(seed_raw) = p.files.read(&offer_path)? else {
        return Err(LatchError::other(
            "no pending clone offer on this machine",
            "run 'latch clone offer' here first, then create the payload against it",
        ));
    };
    if let Some(mtime) = p.files.mtime_unix(&offer_path)? {
        if p.clock.now_unix().saturating_sub(mtime) > OFFER_TTL_SECS {
            p.files.remove(&offer_path)?;
            return Err(LatchError::other(
                "the clone offer has expired (15 minutes)",
                "run 'latch clone offer' again and create a fresh payload",
            ));
        }
    }
    let seed: [u8; 32] = seed_raw.try_into().map_err(|_| LatchError::Format {
        context: OFFER_FILE.into(),
        detail: "corrupt offer secret".into(),
    })?;
    let secret = StaticSecret::from(seed);
    let offer_pub = PublicKey::from(&secret);

    let rest = payload_str
        .trim()
        .strip_prefix(PAYLOAD_PREFIX)
        .ok_or_else(|| LatchError::Format {
            context: "clone payload".into(),
            detail: format!("expected a string starting with {}", PAYLOAD_PREFIX),
        })?;
    let (pub_hex, sealed_hex) = rest.split_once(':').ok_or_else(|| LatchError::Format {
        context: "clone payload".into(),
        detail: "missing ':' separator".into(),
    })?;
    let source_pub_bytes = parse_hex32(pub_hex, "clone payload public key")?;
    let sealed = hex::decode(sealed_hex).map_err(|_| LatchError::Format {
        context: "clone payload".into(),
        detail: "body is not valid hex".into(),
    })?;

    // MITM gate: the code binds BOTH public keys. D5: a wrong code
    // CONSUMES the offer (single-use, as promised) so the low-entropy
    // 6-digit code cannot be brute-forced against a pending offer inside
    // the 15-minute window; the comparison is constant-time.
    let expected = verify_code(offer_pub.as_bytes(), &source_pub_bytes);
    let refuse_and_burn = |p: &Platform, what: &'static str, remedy: &'static str| {
        let _ = p.files.remove(&offer_path);
        Err(LatchError::other(what, remedy))
    };
    match code {
        Some(given) => {
            if !constant_time_eq(given.trim().as_bytes(), expected.as_bytes()) {
                return refuse_and_burn(
                    p,
                    "verify code mismatch — offer discarded",
                    "start over: 'latch clone offer' here, then create a fresh payload (a wrong code burns the offer, by design)",
                );
            }
        }
        None => {
            let ok = p.prompt.confirm(&format!(
                "does the source machine show verify code {}?",
                expected
            ))?;
            if !ok {
                return refuse_and_burn(
                    p,
                    "clone refused — offer discarded",
                    "start over: 'latch clone offer' here, then create a fresh payload",
                );
            }
        }
    }

    let shared = secret.diffie_hellman(&PublicKey::from(source_pub_bytes));
    let key = transport_key(shared.as_bytes(), offer_pub.as_bytes(), &source_pub_bytes);
    let plain = envelope::open(&key, &KeyId::new(CLONE_LABEL, 1)?, &sealed, "clone payload")
        .map_err(|_| {
            LatchError::other(
                "payload cannot be opened with this offer",
                "the payload must be created against THIS machine's current offer — re-run both steps",
            )
        })?;
    let payload: ClonePayload = serde_json::from_slice(&plain).map_err(|e| LatchError::Format {
        context: "clone payload".into(),
        detail: format!("inner json: {}", e),
    })?;

    let store = CredStore::new(p);
    let mut applied = Vec::new();
    for (slot, hexed) in &payload.slots {
        let value = hex::decode(hexed).map_err(|_| LatchError::Format {
            context: format!("clone slot {}", slot),
            detail: "corrupt hex".into(),
        })?;
        store.set(slot, &value)?;
        applied.push(slot.clone());
    }
    let mut repo_configured = false;
    if let Some(repo) = payload.repo {
        let mut cfg = Config::load(p)?;
        if cfg.repo.is_none() {
            cfg.repo = Some(repo);
            cfg.save(p)?;
            repo_configured = true;
        }
    }
    // Single use: a second payload needs a fresh offer.
    p.files.remove(&offer_path)?;
    Ok(ApplyOutcome {
        applied,
        repo_configured,
    })
}

// ── The AR5 wrapper: latch clone --to <ssh> ─────────────────────────────

#[derive(Debug)]
pub struct CloneToOutcome {
    pub applied: usize,
    pub code: String,
}

/// One command runs the whole dance over ssh: remote offer → local create
/// → remote apply. The payload is ciphertext (argv-safe); the code binds
/// the transcript, so a tampered channel fails the apply.
pub fn clone_to(
    p: &Platform,
    target: &str,
    project: Option<&str>,
    env: Option<&str>,
) -> Result<CloneToOutcome, LatchError> {
    validate_ssh_target(target)?;
    let out = p.proc.run(
        "ssh",
        &[target, "latch", "clone", "offer", "--machine"],
        &[],
        None,
    )?;
    if out.status != 0 {
        return Err(LatchError::other(
            format!(
                "remote offer failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            "is latch installed on the target and reachable over ssh?",
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let offer_line = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("OFFER="))
        .ok_or_else(|| {
            LatchError::other(
                "the target did not print an offer",
                "the target's latch is too old — update it (latch update) and retry",
            )
        })?;

    let created = create(p, offer_line, project, env)?;

    let out = p.proc.run(
        "ssh",
        &[
            target,
            "latch",
            "clone",
            "apply",
            "--machine",
            "--code",
            &created.code,
            &created.payload,
        ],
        &[],
        None,
    )?;
    if out.status != 0 {
        return Err(LatchError::other(
            format!(
                "remote apply failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            "run the manual path to see more: latch clone offer (there), latch clone create (here), latch clone apply (there)",
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let applied = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("APPLIED="))
        .and_then(|n| n.parse().ok())
        .unwrap_or(created.slots.len());
    Ok(CloneToOutcome {
        applied,
        code: created.code,
    })
}
