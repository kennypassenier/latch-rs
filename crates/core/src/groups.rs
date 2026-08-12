//! W12 file groups: several env files (across projects) sharing one
//! content, subscribed via a first-line pragma `# latch:group=<name>`.
//!
//! Design as approved (W12a-d):
//! - Groups are global per ENVIRONMENT; content lives once in the repo at
//!   `_groups/<env>/<name>.enc`, sealed with the group's own key
//!   (slot/label `group:<name>.<env>`). Member files in project prefixes
//!   are pragma-only STUBS — the repo never stores the content twice.
//! - Latch keeps a LOCAL baseline per group (fingerprint of the content
//!   at last sync + the member set). At commit, exactly one changed
//!   member becomes the new group content and every other member is
//!   fanned out in the same commit; empty (pragma-only) members are
//!   subscribers, never changes.
//! - Two or more changed members with different content is a hard error
//!   naming the files and the differing keys (W12b); the only choosing
//!   path is `latch group resolve <name> --source <file>`.
//! - A NEW member with content that differs from the group errors with
//!   both intents in the remedy: empty the file to subscribe, or
//!   `latch group adopt <name> --from <file>` (W12c).

use std::collections::{BTreeMap, BTreeSet};

use sha2::Digest;

use crate::config::Config;
use crate::credentials::CredStore;
use crate::envelope::{self, KeyId, KEY_LEN};
use crate::error::LatchError;
use crate::platform::Platform;
use crate::repo::Repo;

pub const PRAGMA_PREFIX: &str = "# latch:group=";

// ── Pragma parsing ──────────────────────────────────────────────────────

/// Split a member file into (group name, body). None = not a group member.
/// The body is everything after the pragma line, pragma excluded.
pub fn parse_member(content: &[u8]) -> Option<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(content);
    let first = text.lines().next()?.trim();
    let name = first.strip_prefix(PRAGMA_PREFIX)?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let body = match text.split_once('\n') {
        Some((_, rest)) => rest.as_bytes().to_vec(),
        None => Vec::new(),
    };
    Some((name.to_string(), body))
}

/// Is this body "empty" in the W12a sense (subscriber, never a change)?
fn body_is_empty(body: &[u8]) -> bool {
    String::from_utf8_lossy(body)
        .lines()
        .all(|l| l.trim().is_empty())
}

/// Reassemble a member file: pragma line + group content.
pub fn member_file(name: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("{}{}\n", PRAGMA_PREFIX, name).into_bytes();
    out.extend_from_slice(body);
    out
}

fn fingerprint(body: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(body))
}

// ── Group keys ──────────────────────────────────────────────────────────

pub fn slot_for(name: &str, env: &str) -> String {
    format!("group:{}.{}", name, env)
}

pub struct GroupKey {
    pub key: [u8; KEY_LEN],
    pub id: KeyId,
}

pub fn key_get(store: &CredStore, name: &str, env: &str) -> Result<Option<GroupKey>, LatchError> {
    let slot = slot_for(name, env);
    let Some((raw, _)) = store.get(&slot)? else {
        return Ok(None);
    };
    if raw.len() != 2 + KEY_LEN {
        return Err(LatchError::Format {
            context: slot,
            detail: format!(
                "stored group key has {} bytes, expected {}",
                raw.len(),
                2 + KEY_LEN
            ),
        });
    }
    let generation = u16::from_le_bytes([raw[0], raw[1]]);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw[2..]);
    Ok(Some(GroupKey {
        key,
        id: KeyId::new(slot_for(name, env), generation)?,
    }))
}

pub fn key_get_or_create(store: &CredStore, name: &str, env: &str) -> Result<GroupKey, LatchError> {
    if let Some(k) = key_get(store, name, env)? {
        return Ok(k);
    }
    let mut key = [0u8; KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let generation: u16 = 1;
    let mut raw = Vec::with_capacity(2 + KEY_LEN);
    raw.extend_from_slice(&generation.to_le_bytes());
    raw.extend_from_slice(&key);
    store.set(&slot_for(name, env), &raw)?;
    Ok(GroupKey {
        key,
        id: KeyId::new(slot_for(name, env), generation)?,
    })
}

/// D2d: mint the next generation of a group key (the old one preserved
/// under a `#prev` slot, exactly like project keys — K3 for groups).
/// Returns (old key, new key); the caller re-seals the group content.
pub fn key_rotate(
    store: &CredStore,
    name: &str,
    env: &str,
) -> Result<(GroupKey, GroupKey), LatchError> {
    let old = key_get(store, name, env)?.ok_or_else(|| {
        LatchError::other(
            format!("group '{}' has no key for env '{}' to rotate", name, env),
            "commit a member first so the group and its key exist",
        )
    })?;
    let mut raw = Vec::with_capacity(2 + KEY_LEN);
    raw.extend_from_slice(&old.id.generation.to_le_bytes());
    raw.extend_from_slice(&old.key);
    store.set(&format!("{}#prev", slot_for(name, env)), &raw)?;

    let generation = old.id.generation + 1;
    let mut key = [0u8; KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let mut raw = Vec::with_capacity(2 + KEY_LEN);
    raw.extend_from_slice(&generation.to_le_bytes());
    raw.extend_from_slice(&key);
    store.set(&slot_for(name, env), &raw)?;
    Ok((
        old,
        GroupKey {
            key,
            id: KeyId::new(slot_for(name, env), generation)?,
        },
    ))
}

/// Clear a group key's preserved previous generation (after re-seal).
pub fn key_clear_prev(store: &CredStore, name: &str, env: &str) -> Result<(), LatchError> {
    store.delete(&format!("{}#prev", slot_for(name, env)))
}

// ── Local baseline state (never in git — this is per-machine memory) ────

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct BaselineFile {
    /// "<env>/<name>" -> baseline
    groups: BTreeMap<String, Baseline>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct Baseline {
    /// sha256 hex of the group content at last sync.
    fingerprint: String,
    /// Known members as "<project>/<relative path>".
    members: BTreeSet<String>,
}

fn baseline_path(p: &Platform) -> String {
    format!("{}/groups.json", p.latch_home)
}

fn baseline_load(p: &Platform) -> Result<BaselineFile, LatchError> {
    match p.files.read(&baseline_path(p))? {
        None => Ok(BaselineFile::default()),
        Some(raw) => serde_json::from_slice(&raw).map_err(|e| LatchError::Format {
            context: baseline_path(p),
            detail: e.to_string(),
        }),
    }
}

fn baseline_save(p: &Platform, file: &BaselineFile) -> Result<(), LatchError> {
    let raw = serde_json::to_vec_pretty(file).expect("baseline serializes");
    p.files.write_atomic(&baseline_path(p), &raw)
}

// ── The commit-time engine ──────────────────────────────────────────────

/// One discovered member of a group.
#[derive(Clone)]
struct Member {
    project: String,
    project_dir: String,
    rel: String,
    body: Vec<u8>,
}

impl Member {
    fn id(&self) -> String {
        format!("{}/{}", self.project, self.rel)
    }
    fn local_path(&self) -> String {
        format!("{}/{}", self.project_dir, self.rel)
    }
}

#[derive(Debug)]
pub struct GroupReport {
    pub name: String,
    /// The group content changed this commit (new content adopted).
    pub changed: bool,
    /// Member files rewritten locally to match the group (fan-out).
    pub fanned_out: Vec<String>,
    /// All current members as "<project>/<rel>".
    pub members: Vec<String>,
}

/// Scan ALL configured projects for group members in `env` files, apply
/// the W12 rules, and write group content + member stubs into the clone.
/// Called from `commit` — the commit IS the group sync point.
pub fn sync_groups(p: &Platform, repo: &Repo, env: &str) -> Result<Vec<GroupReport>, LatchError> {
    let config = Config::load(p)?;
    let store = CredStore::new(p);

    // Collect members per group across every linked project.
    let mut groups: BTreeMap<String, Vec<Member>> = BTreeMap::new();
    for proj in &config.projects {
        for rel in crate::discovery::discover(p.files, &proj.dir)? {
            let Some(raw) = p.files.read(&format!("{}/{}", proj.dir, rel))? else {
                continue;
            };
            if let Some((name, body)) = parse_member(&raw) {
                groups.entry(name).or_default().push(Member {
                    project: proj.name.clone(),
                    project_dir: proj.dir.clone(),
                    rel,
                    body,
                });
            }
        }
    }

    let mut baselines = baseline_load(p)?;
    let mut reports = Vec::new();
    for (name, members) in &groups {
        let report = sync_one_group(p, repo, env, name, members, &store, &mut baselines, None)?;
        reports.push(report);
    }
    baseline_save(p, &baselines)?;
    Ok(reports)
}

/// Core of the W12 rules for one group. `forced_source` (resolve/adopt)
/// bypasses divergence/join errors by naming the winning member id.
#[allow(clippy::too_many_arguments)]
fn sync_one_group(
    p: &Platform,
    repo: &Repo,
    env: &str,
    name: &str,
    members: &[Member],
    store: &CredStore,
    baselines: &mut BaselineFile,
    forced_source: Option<&str>,
) -> Result<GroupReport, LatchError> {
    let gkey = key_get_or_create(store, name, env)?;
    let enc_rel = format!("_groups/{}/{}.enc", env, name);
    let current: Option<Vec<u8>> = match repo.read(&enc_rel)? {
        Some(sealed) => Some(envelope::open(&gkey.key, &gkey.id, &sealed, &enc_rel)?),
        None => None,
    };

    let bkey = format!("{}/{}", env, name);
    let baseline = baselines.groups.get(&bkey).cloned().unwrap_or_default();

    // Classify members.
    let mut candidates: Vec<&Member> = Vec::new(); // changed, known members
    let mut new_with_content: Vec<&Member> = Vec::new(); // W12c cases
    for m in members {
        if body_is_empty(&m.body) {
            continue; // subscriber (W12a) — never a change
        }
        if let Some(cur) = &current {
            if &m.body == cur {
                continue; // in sync
            }
            if fingerprint(&m.body) == baseline.fingerprint {
                continue; // stale: equals the old baseline, fan-out updates it
            }
            if let Some(src) = forced_source {
                if m.id() == src {
                    candidates.push(m);
                }
                continue; // resolve/adopt: everything else is overruled
            }
            if baseline.members.contains(&m.id()) {
                candidates.push(m); // an edit by a known member (W12b candidate)
            } else {
                new_with_content.push(m); // W12c: joining with foreign content
            }
        } else {
            // Founding commit of the group: any non-empty member is a
            // content candidate.
            if forced_source.is_none() || forced_source == Some(m.id().as_str()) {
                candidates.push(m);
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    if forced_source.is_none() {
        if let Some(m) = new_with_content.first() {
            return Err(LatchError::other(
                format!(
                    "{} subscribes to group '{}' but its content differs from the group",
                    m.id(),
                    name
                ),
                format!(
                    "empty the file (keep the pragma) to take the group content, or make its content the group's with 'latch group adopt {} --from {}'",
                    name,
                    m.rel
                ),
            ));
        }
    }

    // Identical content from several members is agreement, not conflict.
    candidates.sort_by(|a, b| a.body.cmp(&b.body));
    candidates.dedup_by(|a, b| a.body == b.body);

    let new_content: Option<Vec<u8>> = match (candidates.len(), &current) {
        (0, Some(_)) => None, // nothing changed
        (0, None) => {
            return Err(LatchError::other(
                format!(
                    "group '{}' has only empty members and no stored content",
                    name
                ),
                "put the intended content in ONE member file under the pragma, then commit again",
            ));
        }
        (1, _) => Some(candidates[0].body.clone()),
        (_, _) => {
            // W12b: divergence. Name the files and the keys that differ.
            let a = crate::ops::edit_diff::parse_env(&String::from_utf8_lossy(&candidates[0].body));
            let b = crate::ops::edit_diff::parse_env(&String::from_utf8_lossy(&candidates[1].body));
            let mut diff_keys: BTreeSet<String> = BTreeSet::new();
            for (k, v) in &a {
                if b.get(k) != Some(v) {
                    diff_keys.insert(k.clone());
                }
            }
            for k in b.keys() {
                if !a.contains_key(k) {
                    diff_keys.insert(k.clone());
                }
            }
            let files: Vec<String> = candidates.iter().map(|m| m.id()).collect();
            return Err(LatchError::other(
                format!(
                    "group '{}' diverged: {} all changed; differing keys: {}",
                    name,
                    files.join(" and "),
                    diff_keys.into_iter().collect::<Vec<_>>().join(", ")
                ),
                format!(
                    "pick the winner explicitly: latch group resolve {} --source <file> (the losing edits are overwritten)",
                    name
                ),
            ));
        }
    };

    let content: Vec<u8> = match (&new_content, &current) {
        (Some(c), _) => c.clone(),
        (None, Some(c)) => c.clone(),
        (None, None) => unreachable!("guarded above"),
    };

    // Write group content into the clone when it changed.
    let changed = new_content.is_some() && current.as_ref() != new_content.as_ref();
    if changed {
        let sealed = envelope::seal(&gkey.key, &gkey.id, &content)?;
        repo.write(&enc_rel, &sealed)?;
    }

    // Fan-out: every member's local file becomes pragma + content, and its
    // stub (pragma only, sealed with the member's PROJECT key) lands in
    // the project prefix so the repo layout stays self-describing (AR9).
    let mut fanned = Vec::new();
    for m in members {
        let full = member_file(name, &content);
        let existing = p.files.read(&m.local_path())?;
        if existing.as_deref() != Some(full.as_slice()) {
            p.files.write_atomic(&m.local_path(), &full)?;
            fanned.push(m.id());
        }
        let pkey = crate::keys::for_env_or_create(store, &m.project, env)?;
        let flat = crate::discovery::flatten(&m.rel)?;
        let stub_rel = format!("{}/{}/{}.enc", m.project, env, flat);
        let stub_plain = member_file(name, b"");
        let write_stub = match repo.read(&stub_rel)? {
            Some(sealed) => !matches!(
                envelope::open(&pkey.key, &pkey.id, &sealed, &stub_rel),
                Ok(prev) if prev == stub_plain
            ),
            None => true,
        };
        if write_stub {
            let sealed = envelope::seal(&pkey.key, &pkey.id, &stub_plain)?;
            repo.write(&stub_rel, &sealed)?;
        }
    }

    baselines.groups.insert(
        bkey,
        Baseline {
            fingerprint: fingerprint(&content),
            members: members.iter().map(|m| m.id()).collect(),
        },
    );

    Ok(GroupReport {
        name: name.to_string(),
        changed,
        fanned_out: fanned,
        members: members.iter().map(|m| m.id()).collect(),
    })
}

// ── Reading group content (pull / run / status integration) ─────────────

/// Decrypt the group's stored content, or a clear error naming the
/// missing key when this machine doesn't hold it.
pub fn group_body(p: &Platform, repo: &Repo, env: &str, name: &str) -> Result<Vec<u8>, LatchError> {
    let store = CredStore::new(p);
    let enc_rel = format!("_groups/{}/{}.enc", env, name);
    let sealed = repo.read(&enc_rel)?.ok_or_else(|| {
        LatchError::other(
            format!("group '{}' has no stored content for env '{}'", name, env),
            "commit a member with content first (the founding member defines the group)",
        )
    })?;
    let gkey = key_get(&store, name, env)?.ok_or_else(|| {
        LatchError::other(
            format!("no key for group '{}' ({}) on this machine", name, env),
            format!(
                "inject it via {} or clone your credentials here (latch clone)",
                crate::credentials::env_var_for_slot(&slot_for(name, env))
            ),
        )
    })?;
    envelope::open(&gkey.key, &gkey.id, &sealed, &enc_rel)
}

/// Register a member + content fingerprint in the local baseline. Pull
/// calls this so a later edit+commit on THIS machine is recognized as a
/// known member's change (W12b) instead of a foreign join (W12c).
pub fn note_baseline(
    p: &Platform,
    env: &str,
    name: &str,
    body: &[u8],
    member_id: &str,
) -> Result<(), LatchError> {
    let mut baselines = baseline_load(p)?;
    let entry = baselines
        .groups
        .entry(format!("{}/{}", env, name))
        .or_default();
    entry.fingerprint = fingerprint(body);
    entry.members.insert(member_id.to_string());
    baseline_save(p, &baselines)
}

// ── The group verbs: list / resolve / adopt ─────────────────────────────

#[derive(Debug)]
pub struct GroupInfo {
    pub name: String,
    pub members: Vec<String>,
    pub has_content: bool,
    pub key_held: bool,
}

/// W12 overview: every group visible in the repo for `env`, plus local
/// members that reference it.
pub fn list(p: &Platform, env: &str) -> Result<Vec<GroupInfo>, LatchError> {
    let repo = crate::ops::consume::repo_handle(p)?;
    repo.ensure()?;
    let _ = repo.refresh(false)?;
    let repo = &repo;
    let config = Config::load(p)?;
    let store = CredStore::new(p);
    let mut names: BTreeSet<String> = BTreeSet::new();
    for enc in repo.list(&format!("_groups/{}", env))? {
        if let Some(n) = enc.strip_suffix(".enc") {
            names.insert(n.to_string());
        }
    }
    let mut members: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for proj in &config.projects {
        for rel in crate::discovery::discover(p.files, &proj.dir)? {
            if let Some(raw) = p.files.read(&format!("{}/{}", proj.dir, rel))? {
                if let Some((name, _)) = parse_member(&raw) {
                    names.insert(name.clone());
                    members
                        .entry(name)
                        .or_default()
                        .push(format!("{}/{}", proj.name, rel));
                }
            }
        }
    }
    let mut out = Vec::new();
    for name in names {
        out.push(GroupInfo {
            members: members.remove(&name).unwrap_or_default(),
            has_content: repo
                .read(&format!("_groups/{}/{}.enc", env, name))?
                .is_some(),
            key_held: key_get(&store, &name, env)?.is_some(),
            name,
        });
    }
    Ok(out)
}

/// W12b escape hatch + W12c adopt: make `source_rel` (a file in the cwd
/// project) THE group content, overwriting every other member.
pub fn resolve(
    p: &Platform,
    cwd: &str,
    env: &str,
    name: &str,
    source_rel: &str,
) -> Result<GroupReport, LatchError> {
    let _lock = crate::lock::acquire(p, 10, || {})?;
    let repo = crate::ops::consume::repo_handle(p)?;
    repo.ensure()?;
    let repo = &repo;
    let proj = crate::ops::sync::project_for(p, cwd)?;
    let source_id = format!("{}/{}", proj.name, source_rel);

    let config = Config::load(p)?;
    let store = CredStore::new(p);
    let mut members: Vec<Member> = Vec::new();
    for pr in &config.projects {
        for rel in crate::discovery::discover(p.files, &pr.dir)? {
            if let Some(raw) = p.files.read(&format!("{}/{}", pr.dir, rel))? {
                if let Some((n, body)) = parse_member(&raw) {
                    if n == name {
                        members.push(Member {
                            project: pr.name.clone(),
                            project_dir: pr.dir.clone(),
                            rel,
                            body,
                        });
                    }
                }
            }
        }
    }
    let Some(src) = members.iter().find(|m| m.id() == source_id) else {
        return Err(LatchError::other(
            format!("'{}' is not a member of group '{}'", source_rel, name),
            format!("the file needs the first line '{}{}'", PRAGMA_PREFIX, name),
        ));
    };
    if body_is_empty(&src.body) {
        return Err(LatchError::other(
            format!(
                "'{}' is empty — it cannot define the group content",
                source_rel
            ),
            "pick a member that holds the intended content",
        ));
    }

    let mut baselines = baseline_load(p)?;
    let report = sync_one_group(
        p,
        repo,
        env,
        name,
        &members,
        &store,
        &mut baselines,
        Some(&source_id),
    )?;
    baseline_save(p, &baselines)?;
    Ok(report)
}
