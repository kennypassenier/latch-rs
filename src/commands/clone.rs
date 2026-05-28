use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, stdin};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{
    global::{GlobalConfig, ProjectEntry},
    latch_home,
};
use crate::credentials::{
    get_global_pat, get_global_secrets_repo, keyring_provider::KeyringProvider,
};
use crate::crypto::{decrypt, encrypt};
use crate::github::{RemoteStorage as _, client::GitHubClient};
use crate::manifest::Manifest;

const CLONE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct CloneOffer {
    pub version: u32,
    pub offer_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub recipient_public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredOffer {
    offer_id: String,
    created_at: u64,
    expires_at: u64,
    recipient_secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloneEntry {
    slot: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectMeta {
    name: String,
    secrets_repo: String,
    default_env: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CloneBundle {
    version: u32,
    created_at: u64,
    source_host: String,
    projects: Vec<ProjectMeta>,
    entries: Vec<CloneEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClonePayload {
    pub version: u32,
    pub offer_id: String,
    pub created_at: u64,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
}

fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX_EPOCH")?
        .as_secs())
}

fn clone_offer_dir() -> PathBuf {
    latch_home().join("clone_offers")
}

fn clone_offer_path(offer_id: &str) -> PathBuf {
    clone_offer_dir().join(format!("{}.json", offer_id))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn parse_offer_input(offer: Option<&str>, offer_file: Option<&str>) -> Result<CloneOffer> {
    let raw = if let Some(text) = offer {
        text.to_string()
    } else if let Some(path) = offer_file {
        fs::read_to_string(path).with_context(|| format!("Reading offer file {}", path))?
    } else {
        bail!("Provide either --offer or --offer-file")
    };

    serde_json::from_str(&raw).context("Parsing clone offer JSON")
}

fn parse_payload_input(payload: Option<&str>, payload_file: Option<&str>) -> Result<ClonePayload> {
    let raw = if let Some(text) = payload {
        text.to_string()
    } else if let Some(path) = payload_file {
        fs::read_to_string(path).with_context(|| format!("Reading payload file {}", path))?
    } else {
        let mut buf = String::new();
        stdin()
            .read_to_string(&mut buf)
            .context("Reading payload from stdin")?;
        if buf.trim().is_empty() {
            bail!("Provide --payload, --payload-file, or pipe JSON on stdin")
        }
        buf
    };

    serde_json::from_str(&raw).context("Parsing clone payload JSON")
}

fn key_from_shared(shared: [u8; 32]) -> [u8; 32] {
    shared
}

async fn discover_project_envs(project: &ProjectEntry, pat: Option<&str>) -> BTreeSet<String> {
    let mut envs = BTreeSet::new();
    envs.insert(project.default_env.clone());

    let Some(pat) = pat else {
        return envs;
    };
    let Ok(client) = GitHubClient::new(&project.secrets_repo, pat) else {
        return envs;
    };

    let manifest_path = Manifest::remote_path(&project.name);
    let Ok(bytes) = client.pull_file(&manifest_path).await else {
        return envs;
    };
    let Ok(manifest) = Manifest::from_bytes(&bytes) else {
        return envs;
    };

    for env_name in manifest.envs.keys() {
        envs.insert(env_name.clone());
    }

    envs
}

pub async fn offer(ttl_minutes: u64) -> Result<()> {
    let created_at = now_epoch()?;
    let expires_at = created_at.saturating_add(ttl_minutes.saturating_mul(60));

    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let recipient_secret = StaticSecret::from(secret_bytes);
    let recipient_public = PublicKey::from(&recipient_secret);

    let offer_id = random_hex(8);

    fs::create_dir_all(clone_offer_dir()).context("Creating clone offer directory")?;

    let stored = StoredOffer {
        offer_id: offer_id.clone(),
        created_at,
        expires_at,
        recipient_secret_key: base64::engine::general_purpose::STANDARD.encode(secret_bytes),
    };

    let stored_path = clone_offer_path(&offer_id);
    fs::write(&stored_path, serde_json::to_vec_pretty(&stored)?)
        .with_context(|| format!("Writing {}", stored_path.display()))?;

    let public_offer = CloneOffer {
        version: CLONE_VERSION,
        offer_id,
        created_at,
        expires_at,
        recipient_public_key: base64::engine::general_purpose::STANDARD
            .encode(recipient_public.as_bytes()),
    };

    println!("{}", serde_json::to_string(&public_offer)?);
    Ok(())
}

pub async fn create(offer: Option<&str>, offer_file: Option<&str>) -> Result<()> {
    let parsed_offer = parse_offer_input(offer, offer_file)?;
    if parsed_offer.version != CLONE_VERSION {
        bail!(
            "Unsupported offer version {} (expected {})",
            parsed_offer.version,
            CLONE_VERSION
        );
    }

    let now = now_epoch()?;
    if now > parsed_offer.expires_at {
        bail!("Clone offer has expired");
    }

    let recipient_pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(parsed_offer.recipient_public_key.as_bytes())
        .context("Decoding recipient public key")?;
    let recipient_pub_arr: [u8; 32] = recipient_pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Recipient public key must be 32 bytes"))?;
    let recipient_pub = PublicKey::from(recipient_pub_arr);

    let mut ephemeral_secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ephemeral_secret_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

    let mut entries: Vec<CloneEntry> = Vec::new();

    if let Some(v) = get_global_pat() {
        entries.push(CloneEntry {
            slot: "github.pat".to_string(),
            value: v,
        });
    }
    if let Some(v) = get_global_secrets_repo() {
        entries.push(CloneEntry {
            slot: "github.secrets_repo".to_string(),
            value: v,
        });
    }

    let global = GlobalConfig::load().unwrap_or_default();
    let mut projects: Vec<ProjectMeta> = Vec::new();

    for p in &global.projects {
        projects.push(ProjectMeta {
            name: p.name.clone(),
            secrets_repo: p.secrets_repo.clone(),
            default_env: p.default_env.clone(),
        });

        if let Some(v) = KeyringProvider::get_raw(&format!("{}.key", p.name)) {
            entries.push(CloneEntry {
                slot: format!("{}.key", p.name),
                value: v,
            });
        }

        if let Some(v) = KeyringProvider::get_raw(&format!("{}.pat", p.name)) {
            entries.push(CloneEntry {
                slot: format!("{}.pat", p.name),
                value: v,
            });
        }

        let pat_for_manifest = get_global_pat()
            .or_else(|| KeyringProvider::get_raw(&format!("{}.pat", p.name)))
            .or_else(|| p.github_pat.clone());

        let envs = discover_project_envs(p, pat_for_manifest.as_deref()).await;
        for env_name in envs {
            let slot = format!("{}.key.{}", p.name, env_name);
            if let Some(v) = KeyringProvider::get_raw(&slot) {
                entries.push(CloneEntry { slot, value: v });
            }
        }
    }

    entries.sort_by(|a, b| a.slot.cmp(&b.slot));
    entries.dedup_by(|a, b| a.slot == b.slot && a.value == b.value);

    let bundle = CloneBundle {
        version: CLONE_VERSION,
        created_at: now,
        source_host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
        projects,
        entries,
    };

    let bundle_bytes = serde_json::to_vec(&bundle)?;
    let key = key_from_shared(*shared.as_bytes());
    let ciphertext = encrypt(&bundle_bytes, &key)?;

    let payload = ClonePayload {
        version: CLONE_VERSION,
        offer_id: parsed_offer.offer_id,
        created_at: now,
        ephemeral_public_key: base64::engine::general_purpose::STANDARD
            .encode(ephemeral_public.as_bytes()),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    };

    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

pub async fn apply(payload: Option<&str>, payload_file: Option<&str>) -> Result<()> {
    let parsed_payload = parse_payload_input(payload, payload_file)?;
    if parsed_payload.version != CLONE_VERSION {
        bail!(
            "Unsupported payload version {} (expected {})",
            parsed_payload.version,
            CLONE_VERSION
        );
    }

    let offer_path = clone_offer_path(&parsed_payload.offer_id);
    let stored: StoredOffer = serde_json::from_slice(
        &fs::read(&offer_path).with_context(|| format!("Reading {}", offer_path.display()))?,
    )
    .context("Parsing stored clone offer")?;

    let now = now_epoch()?;
    if now > stored.expires_at {
        bail!("Stored clone offer has expired")
    }

    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(stored.recipient_secret_key.as_bytes())
        .context("Decoding stored recipient secret key")?;
    let secret_arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Recipient secret key must be 32 bytes"))?;
    let recipient_secret = StaticSecret::from(secret_arr);

    let eph_bytes = base64::engine::general_purpose::STANDARD
        .decode(parsed_payload.ephemeral_public_key.as_bytes())
        .context("Decoding ephemeral public key")?;
    let eph_arr: [u8; 32] = eph_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ephemeral public key must be 32 bytes"))?;
    let eph_pub = PublicKey::from(eph_arr);

    let shared = recipient_secret.diffie_hellman(&eph_pub);
    let key = key_from_shared(*shared.as_bytes());

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(parsed_payload.ciphertext.as_bytes())
        .context("Decoding payload ciphertext")?;
    let plaintext = decrypt(&ciphertext, &key)?;

    let bundle: CloneBundle = serde_json::from_slice(&plaintext).context("Parsing clone bundle")?;

    for entry in &bundle.entries {
        KeyringProvider::set_raw(&entry.slot, &entry.value)
            .with_context(|| format!("Writing keyring slot {}", entry.slot))?;
    }

    let mut global = GlobalConfig::load().unwrap_or_default();
    for p in &bundle.projects {
        let current = global
            .get_project(&p.name)
            .cloned()
            .unwrap_or(ProjectEntry {
                name: p.name.clone(),
                secrets_repo: p.secrets_repo.clone(),
                default_env: p.default_env.clone(),
                key_hex: None,
                github_pat: None,
            });

        global.upsert_project(ProjectEntry {
            name: p.name.clone(),
            secrets_repo: p.secrets_repo.clone(),
            default_env: p.default_env.clone(),
            key_hex: current.key_hex,
            github_pat: current.github_pat,
        });
    }
    global.save()?;

    let _ = fs::remove_file(&offer_path);

    println!(
        "Applied clone payload. Restored {} keyring entries across {} project metadata record(s).",
        bundle.entries.len(),
        bundle.projects.len()
    );
    Ok(())
}
