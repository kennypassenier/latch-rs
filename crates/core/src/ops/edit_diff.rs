//! W10 diff (masked by default) and W11 zero-disk edit, plus D3 example
//! generation (explicitly flagged, never a default side effect).

use std::collections::BTreeMap;

use crate::credentials::CredStore;
use crate::discovery;
use crate::envelope;
use crate::error::LatchError;
use crate::keys;
use crate::lock;
use crate::platform::Platform;

use super::consume::repo_handle;
use super::sync::project_for;

/// Parse KEY=VALUE lines (comments/blanks skipped).
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(
                k.trim().to_string(),
                v.trim().trim_matches('"').trim_matches('\'').to_string(),
            );
        }
    }
    out
}

// ── W10 · diff ──────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Removed,
    Changed,
}

#[derive(Debug)]
pub struct FileDiff {
    pub file: String,
    /// (key, change, old value, new value) — values None when masked.
    pub entries: Vec<(String, Change, Option<String>, Option<String>)>,
}

/// Local working tree vs. the committed clone version, per file. Values
/// are withheld unless `reveal` (the masked view is the default — W10).
pub fn diff(p: &Platform, cwd: &str, env: &str, reveal: bool) -> Result<Vec<FileDiff>, LatchError> {
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    repo.ensure()?;
    let store = CredStore::new(p);
    let key = keys::for_env(&store, &proj.name, env)?;
    let prefix = format!("{}/{}", proj.name, env);

    let mut out = Vec::new();
    for rel in discovery::discover(p.files, &proj.dir)? {
        let local_text = p
            .files
            .read(&format!("{}/{}", proj.dir, rel))?
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        let committed_text = match (&key, {
            let flat = discovery::flatten(&rel)?;
            repo.read(&format!("{}/{}.enc", prefix, flat))?
        }) {
            (Some(k), Some(sealed)) => {
                String::from_utf8_lossy(&envelope::open(&k.key, &k.id, &sealed, &rel)?).to_string()
            }
            _ => String::new(),
        };
        let local = parse_env(&local_text);
        let committed = parse_env(&committed_text);

        let mut entries = Vec::new();
        for (k, v) in &local {
            match committed.get(k) {
                None => entries.push((k.clone(), Change::Added, None, reveal.then(|| v.clone()))),
                Some(old) if old != v => entries.push((
                    k.clone(),
                    Change::Changed,
                    reveal.then(|| old.clone()),
                    reveal.then(|| v.clone()),
                )),
                _ => {}
            }
        }
        for k in committed.keys() {
            if !local.contains_key(k) {
                entries.push((
                    k.clone(),
                    Change::Removed,
                    reveal.then(|| committed[k].clone()),
                    None,
                ));
            }
        }
        if !entries.is_empty() {
            out.push(FileDiff { file: rel, entries });
        }
    }
    Ok(out)
}

// ── W11 · edit ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct EditOutcome {
    pub changed: bool,
    pub file: String,
}

/// Open one env file's COMMITTED content in $EDITOR via a tmpfs file
/// (never the physical disk); on close, changed content is encrypted into
/// the clone immediately. The local working-tree file is updated too so
/// status stays clean. Push remains an explicit step.
pub fn edit(
    p: &Platform,
    cwd: &str,
    env: &str,
    file: Option<&str>,
) -> Result<EditOutcome, LatchError> {
    let proj = project_for(p, cwd)?;
    let repo = repo_handle(p)?;
    let store = CredStore::new(p);

    let rel = file.unwrap_or(".env").to_string();
    let flat = discovery::flatten(&rel)?;
    let enc_rel = format!("{}/{}/{}.enc", proj.name, env, flat);

    // Read the current content under the lock, then RELEASE it before the
    // editor runs (B3: holding the mutation lock across an interactive
    // $EDITOR session is exactly what let its 15-minute stale-break hand
    // the lock to a concurrent process). The editor sees a tmpfs copy;
    // the write below re-acquires the lock.
    let (key, current) = {
        let _lock = lock::acquire(p, 10, || {})?;
        repo.ensure()?;
        let key = keys::for_env_or_create(&store, &proj.name, env)?;
        let current = match repo.read(&enc_rel)? {
            Some(sealed) => envelope::open(&key.key, &key.id, &sealed, &rel)?,
            None => p
                .files
                .read(&format!("{}/{}", proj.dir, rel))?
                .unwrap_or_default(),
        };
        (key, current)
    };

    let Some(runtime) = &p.runtime_dir else {
        return Err(LatchError::other(
            "no tmpfs runtime directory available for zero-disk editing",
            "set XDG_RUNTIME_DIR (systemd session) — latch edit refuses to put plaintext on a real disk",
        ));
    };
    let tmp_path = format!("{}/edit-{}-{}", runtime, proj.name, flat);
    p.files.write_atomic(&tmp_path, &current)?;

    let editor = p
        .env
        .var("VISUAL")
        .or_else(|| p.env.var("EDITOR"))
        .unwrap_or_else(|| "vi".into());
    let status = p.proc.exec_interactive(&editor, &[&tmp_path], &[]);
    let edited = p.files.read(&tmp_path)?;
    p.files.remove(&tmp_path)?; // nothing left behind, success or not
    status?;
    let edited =
        edited.ok_or_else(|| LatchError::other("the editor removed the temp file", "retry"))?;

    if edited == current {
        return Ok(EditOutcome {
            changed: false,
            file: rel,
        });
    }

    // Re-acquire the lock only for the quick encrypt-and-write. Re-open
    // the repo so we commit against fresh state.
    let _lock = lock::acquire(p, 10, || {})?;
    repo.ensure()?;
    let sealed = envelope::seal(&key.key, &key.id, &edited)?;
    repo.write(&enc_rel, &sealed)?;
    p.files
        .write_atomic(&format!("{}/{}", proj.dir, rel), &edited)?;
    Ok(EditOutcome {
        changed: true,
        file: rel,
    })
}

// ── D3 · example generation (explicit flag only) ────────────────────────

/// Write `.env.example` siblings with keys only — values provably absent.
pub fn write_examples(p: &Platform, cwd: &str) -> Result<Vec<String>, LatchError> {
    let proj = project_for(p, cwd)?;
    let mut written = Vec::new();
    for rel in discovery::discover(p.files, &proj.dir)? {
        let Some(raw) = p.files.read(&format!("{}/{}", proj.dir, rel))? else {
            continue;
        };
        let vars = parse_env(&String::from_utf8_lossy(&raw));
        let mut example = String::new();
        for k in vars.keys() {
            example.push_str(k);
            example.push_str("=\n");
        }
        let path = format!("{}/{}.example", proj.dir, rel);
        p.files.write_atomic(&path, example.as_bytes())?;
        written.push(format!("{}.example", rel));
    }
    Ok(written)
}
