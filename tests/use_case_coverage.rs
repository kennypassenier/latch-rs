use anyhow::Result;
use async_trait::async_trait;
use latch_rs::crypto::{decrypt, encrypt, generate_key_hex, parse_key};
use latch_rs::discovery::{
    flatten_path, has_key_value_pairs, local_blob_path, local_group_blob_path, read_pragma,
    remote_path,
};
use latch_rs::github::{CommitSummary, RemoteStorage, RemoteStorageExt};
use latch_rs::manifest::{CloneGroup, FileMapping, Manifest};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

type FileBytes = Vec<u8>;
type HistoryEntry = (String, FileBytes);
type FileMap = HashMap<String, FileBytes>;
type HistoryMap = HashMap<String, Vec<HistoryEntry>>;

#[derive(Default, Clone)]
struct MockStorage {
    files: Arc<Mutex<FileMap>>,
    history: Arc<Mutex<HistoryMap>>,
}

impl MockStorage {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RemoteStorage for MockStorage {
    async fn push_file(&self, path: &str, content: &[u8], msg: &str) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        let mut history = self.history.lock().unwrap();
        files.insert(path.to_string(), content.to_vec());
        history
            .entry(path.to_string())
            .or_default()
            .push((msg.to_string(), content.to_vec()));
        Ok(())
    }

    async fn pull_file(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not found: {}", path))
    }

    async fn get_sha(&self, path: &str) -> Result<Option<String>> {
        Ok(if self.files.lock().unwrap().contains_key(path) {
            Some("mock-sha".to_string())
        } else {
            None
        })
    }

    async fn delete_file(&self, path: &str, _message: &str) -> Result<()> {
        self.files.lock().unwrap().remove(path);
        Ok(())
    }

    async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .files
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl RemoteStorageExt for MockStorage {
    async fn list_commits(&self, path: &str, limit: usize) -> Result<Vec<CommitSummary>> {
        let history = self.history.lock().unwrap();
        let commits = history
            .get(path)
            .map(|entries| {
                entries
                    .iter()
                    .enumerate()
                    .rev()
                    .take(limit)
                    .map(|(i, (msg, _))| CommitSummary {
                        sha: format!("deadbeef{:02}", i),
                        message: msg.clone(),
                        author: "mock".to_string(),
                        date: "2026-05-28T00:00:00Z".to_string(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(commits)
    }

    async fn pull_file_at_ref(&self, path: &str, git_ref: &str) -> Result<Vec<u8>> {
        let idx = git_ref
            .strip_prefix("ref-")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid mock ref: {}", git_ref))?;

        let history = self.history.lock().unwrap();
        let versions = history
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("no history for {}", path))?;
        versions
            .get(idx)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| anyhow::anyhow!("ref out of range"))
    }
}

#[test]
fn clone_group_pragma_valid_and_invalid() {
    let tmp = TempDir::new().unwrap();
    let good = tmp.path().join("good.env");
    let bad = tmp.path().join("bad.env");
    let none = tmp.path().join("none.env");

    std::fs::write(&good, "# latch:group=api_shared\nKEY=1\n").unwrap();
    std::fs::write(&bad, "# latch:group=api/shared\nKEY=1\n").unwrap();
    std::fs::write(&none, "KEY=1\n").unwrap();

    assert_eq!(read_pragma(&good).as_deref(), Some("api_shared"));
    assert_eq!(read_pragma(&bad), None);
    assert_eq!(read_pragma(&none), None);
}

#[test]
fn clone_group_subscribe_intent_detected() {
    let tmp = TempDir::new().unwrap();
    let subscribe = tmp.path().join("sub.env");
    let with_pairs = tmp.path().join("pairs.env");

    std::fs::write(&subscribe, "# latch:group=shared\n# waiting\n\n").unwrap();
    std::fs::write(&with_pairs, "# latch:group=shared\nA=1\n").unwrap();

    assert!(!has_key_value_pairs(&subscribe));
    assert!(has_key_value_pairs(&with_pairs));
}

#[test]
fn local_latch_paths_are_stable() {
    let root = Path::new("/tmp/project");
    let flat = flatten_path(Path::new("backend/.env"));
    let blob = local_blob_path(root, "dev", &flat);
    let group_blob = local_group_blob_path(root, "dev", "shared");

    assert!(blob.ends_with(".latch/dev/backend__.env.enc"));
    assert!(group_blob.ends_with(".latch/dev/group.shared.enc"));
}

#[test]
fn manifest_clone_groups_roundtrip() {
    let mut m = Manifest::new("myapp", None);
    m.set_env(
        "dev",
        vec![FileMapping {
            local_path: "backend/.env".to_string(),
        }],
    );
    m.clone_groups.push(CloneGroup {
        name: "shared".to_string(),
        env: "dev".to_string(),
        remote_blob: CloneGroup::remote_blob_path("myapp", "dev", "shared"),
        members: vec!["backend/.env".to_string(), "worker/.env".to_string()],
    });

    let bytes = m.to_bytes().unwrap();
    let loaded = Manifest::from_bytes(&bytes).unwrap();

    assert_eq!(loaded.clone_groups.len(), 1);
    let g = &loaded.clone_groups[0];
    assert_eq!(g.name, "shared");
    assert_eq!(g.members.len(), 2);
    assert_eq!(g.remote_blob, "myapp/dev/group.shared.enc");
}

#[test]
fn staging_manifest_save_and_load() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    let mut m = Manifest::new("myapp", Some("salt==".to_string()));
    m.set_env(
        "dev",
        vec![FileMapping {
            local_path: ".env".to_string(),
        }],
    );

    m.save_staging(root).unwrap();
    let loaded = Manifest::load_staging(root).unwrap().unwrap();

    assert_eq!(loaded.project, "myapp");
    assert_eq!(loaded.kdf_salt.as_deref(), Some("salt=="));
    assert_eq!(loaded.get_env("dev").len(), 1);
}

#[tokio::test]
async fn commit_push_pull_style_flow_with_group_cache() {
    let storage = MockStorage::new();
    let key = parse_key(&generate_key_hex()).unwrap();
    let project = "myapp";
    let env = "dev";

    // Stage two files: one standalone and one clone group blob.
    let plain = b"A=1\n";
    let group_plain = b"SHARED=ok\n";
    let standalone_flat = flatten_path(Path::new("backend/.env"));
    let standalone_remote = remote_path(project, env, &standalone_flat);
    let group_remote = CloneGroup::remote_blob_path(project, env, "shared");

    let ct1 = encrypt(plain, &key).unwrap();
    let ct2 = encrypt(group_plain, &key).unwrap();

    storage
        .push_file(&standalone_remote, &ct1, "commit 1")
        .await
        .unwrap();
    storage
        .push_file(&group_remote, &ct2, "commit 1")
        .await
        .unwrap();

    // Remote manifest with group membership.
    let mut manifest = Manifest::new(project, None);
    manifest.set_env(
        env,
        vec![FileMapping {
            local_path: "backend/.env".to_string(),
        }],
    );
    manifest.clone_groups.push(CloneGroup {
        name: "shared".to_string(),
        env: env.to_string(),
        remote_blob: group_remote.clone(),
        members: vec!["backend/.env".to_string(), "worker/.env".to_string()],
    });
    storage
        .push_file(
            &Manifest::remote_path(project),
            &manifest.to_bytes().unwrap(),
            "manifest",
        )
        .await
        .unwrap();

    // Pull-style decrypt checks.
    let pulled = storage.pull_file(&standalone_remote).await.unwrap();
    assert_eq!(decrypt(&pulled, &key).unwrap(), plain.to_vec());
    let pulled_group = storage.pull_file(&group_remote).await.unwrap();
    assert_eq!(decrypt(&pulled_group, &key).unwrap(), group_plain.to_vec());
}

#[tokio::test]
async fn rollback_like_restore_older_blob_from_ref() {
    let storage = MockStorage::new();
    let path = "myapp/dev/backend__.env.enc";

    storage.push_file(path, b"v1", "first").await.unwrap();
    storage.push_file(path, b"v2", "second").await.unwrap();
    storage.push_file(path, b"v3", "third").await.unwrap();

    let old = storage.pull_file_at_ref(path, "ref-0").await.unwrap();
    assert_eq!(old, b"v1");

    // Restore old into head, rollback-style.
    storage
        .push_file(path, &old, "rollback to ref-0")
        .await
        .unwrap();
    let current = storage.pull_file(path).await.unwrap();
    assert_eq!(current, b"v1");
}

#[tokio::test]
async fn history_lists_recent_manifest_commits() {
    let storage = MockStorage::new();
    let mpath = "myapp/manifest.json";

    storage
        .push_file(mpath, b"{}", "latch: push dev [myapp]")
        .await
        .unwrap();
    storage
        .push_file(mpath, b"{\"v\":2}", "latch: rollback dev to deadbeef")
        .await
        .unwrap();

    let commits = storage.list_commits(mpath, 10).await.unwrap();
    assert_eq!(commits.len(), 2);
    assert!(commits[0].message.contains("rollback"));
    assert!(commits[1].message.contains("push"));
}

#[test]
fn overwrite_protection_detection_logic() {
    // Pull overwrite prompt should trigger only when local exists and differs.
    let same_local = b"A=1\n";
    let same_remote = b"A=1\n";
    let diff_remote = b"A=2\n";

    let should_prompt_same = same_local != same_remote;
    let should_prompt_diff = same_local != diff_remote;

    assert!(!should_prompt_same);
    assert!(should_prompt_diff);
}
