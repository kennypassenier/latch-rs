/// Integration tests using a mock RemoteStorage implementation.
use anyhow::Result;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use latch_rs::github::RemoteStorage;

// ── Mock implementation ───────────────────────────────────────────────────────

/// In-memory RemoteStorage for use in tests.
#[derive(Default, Clone)]
pub struct MockStorage {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, path: &str, content: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), content.to_vec());
    }

    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).cloned()
    }

    pub fn all_paths(&self) -> Vec<String> {
        self.files.lock().unwrap().keys().cloned().collect()
    }
}

#[async_trait]
impl RemoteStorage for MockStorage {
    async fn push_file(&self, path: &str, content: &[u8], _message: &str) -> Result<()> {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), content.to_vec());
        Ok(())
    }

    async fn pull_file(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("File not found: {}", path))
    }

    async fn get_sha(&self, path: &str) -> Result<Option<String>> {
        let exists = self.files.lock().unwrap().contains_key(path);
        if exists {
            Ok(Some("mock-sha-abc123".to_string()))
        } else {
            Ok(None)
        }
    }

    async fn delete_file(&self, path: &str, _message: &str) -> Result<()> {
        self.files.lock().unwrap().remove(path);
        Ok(())
    }

    async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mock_push_and_pull_roundtrip() {
    let storage = MockStorage::new();
    let data = b"encrypted content";
    storage
        .push_file("proj/dev/file.enc", data, "test")
        .await
        .unwrap();
    let pulled = storage.pull_file("proj/dev/file.enc").await.unwrap();
    assert_eq!(data.to_vec(), pulled);
}

#[tokio::test]
async fn mock_get_sha_returns_none_for_missing_file() {
    let storage = MockStorage::new();
    let sha = storage.get_sha("nonexistent/file.enc").await.unwrap();
    assert!(sha.is_none());
}

#[tokio::test]
async fn mock_get_sha_returns_some_for_existing_file() {
    let storage = MockStorage::new();
    storage.seed("myapp/manifest.json", b"{}");
    let sha = storage.get_sha("myapp/manifest.json").await.unwrap();
    assert!(sha.is_some());
}

#[tokio::test]
async fn mock_pull_missing_file_errors() {
    let storage = MockStorage::new();
    let result = storage.pull_file("missing.enc").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn mock_list_files_by_prefix() {
    let storage = MockStorage::new();
    storage.seed("proj/dev/a.enc", b"a");
    storage.seed("proj/dev/b.enc", b"b");
    storage.seed("proj/prod/c.enc", b"c");

    let dev_files = storage.list_files("proj/dev/").await.unwrap();
    assert_eq!(dev_files.len(), 2);
    assert!(dev_files.iter().all(|p| p.starts_with("proj/dev/")));
}

#[tokio::test]
async fn mock_delete_file_removes_entry() {
    let storage = MockStorage::new();
    storage.seed("proj/dev/a.enc", b"a");

    storage
        .delete_file("proj/dev/a.enc", "cleanup")
        .await
        .unwrap();

    assert!(!storage.all_paths().iter().any(|p| p == "proj/dev/a.enc"));
}

/// End-to-end: encrypt → push → pull → decrypt using mock storage.
#[tokio::test]
async fn encrypt_push_pull_decrypt_roundtrip() {
    use latch_rs::crypto::{decrypt, encrypt, generate_key_hex, parse_key};
    use latch_rs::discovery::{flatten_path, remote_path};
    use std::path::Path;

    let storage = MockStorage::new();
    let key_hex = generate_key_hex();
    let key = parse_key(&key_hex).unwrap();

    let project = "myapp";
    let env = "dev";
    let local_path = Path::new("backend/.env");
    let plaintext = b"SECRET=super_secret\nDB=postgres://localhost/dev\n";

    let flat = flatten_path(local_path);
    let remote = remote_path(project, env, &flat);

    // Encrypt and push
    let ciphertext = encrypt(plaintext, &key).unwrap();
    storage
        .push_file(&remote, &ciphertext, "test commit")
        .await
        .unwrap();

    // Pull and decrypt
    let pulled = storage.pull_file(&remote).await.unwrap();
    let decrypted = decrypt(&pulled, &key).unwrap();

    assert_eq!(plaintext.to_vec(), decrypted);
    assert_eq!(remote, "myapp/dev/backend.env.enc");
}
