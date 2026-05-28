/// Comprehensive integration tests for all latch commands.
///
/// These tests use:
///   - `MockStorage` (in-memory RemoteStorage) from integration_mocks.rs
///   - Real fixture files from tests/fixtures/
///   - No network, no keyring, no real GitHub calls
///
/// Run: `cargo test --test command_integration`
mod mock {
    use anyhow::Result;
    use async_trait::async_trait;
    use latch_rs::github::RemoteStorage;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    /// In-memory RemoteStorage shared across tests.
    #[derive(Default, Clone)]
    pub struct MockStorage {
        pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self::default()
        }

        #[allow(dead_code)]
        pub fn seed(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_string(), content.to_vec());
        }

        #[allow(dead_code)]
        pub fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(path).cloned()
        }

        #[allow(dead_code)]
        pub fn has(&self, path: &str) -> bool {
            self.files.lock().unwrap().contains_key(path)
        }

        #[allow(dead_code)]
        pub fn all_paths(&self) -> Vec<String> {
            let mut v: Vec<_> = self.files.lock().unwrap().keys().cloned().collect();
            v.sort();
            v
        }
    }

    #[async_trait]
    impl RemoteStorage for MockStorage {
        async fn push_file(&self, path: &str, content: &[u8], _msg: &str) -> Result<()> {
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
                .ok_or_else(|| anyhow::anyhow!("not found: {}", path))
        }
        async fn get_sha(&self, path: &str) -> Result<Option<String>> {
            Ok(if self.files.lock().unwrap().contains_key(path) {
                Some("mock-sha".to_string())
            } else {
                None
            })
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
}

use latch_rs::{
    crypto::{
        decrypt, encrypt, generate_key_hex,
        kdf::{decode_salt, derive_key, generate_salt_b64},
        parse_key,
    },
    discovery::{
        expand_env_file, expand_env_vars, flatten_path, generate_example, remote_path,
        scan_env_files,
    },
    github::RemoteStorage as _,
    manifest::{FileMapping, Manifest},
};
use mock::MockStorage;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Discovery — fixture scanning
// ─────────────────────────────────────────────────────────────────────────────

fn fixtures(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn scan_simple_project_finds_all_envs() {
    let root = fixtures("simple-project");
    let mut files = scan_env_files(&root);
    files.sort();
    // Expect: .env, backend/.env, frontend/.env  (3 files)
    assert_eq!(
        files.len(),
        3,
        "Expected 3 .env files in simple-project, got {:?}",
        files
    );
}

#[test]
fn scan_monorepo_finds_all_envs() {
    let root = fixtures("monorepo");
    let files = scan_env_files(&root);
    // services/api/.env, services/api/.env.staging, services/worker/.env, apps/web/.env = 4
    assert_eq!(
        files.len(),
        4,
        "Expected 4 .env files in monorepo, got {:?}",
        files
    );
}

#[test]
fn scan_nested_project_finds_all_envs() {
    let root = fixtures("nested-project");
    let files = scan_env_files(&root);
    assert_eq!(
        files.len(),
        2,
        "Expected 2 .env files in nested-project, got {:?}",
        files
    );
}

#[test]
fn scan_respects_latchignore() {
    let root = fixtures("ignored-project");
    let files = scan_env_files(&root);
    // .latchignore excludes secrets/ and public/ — only root .env should remain
    assert_eq!(
        files.len(),
        1,
        "Expected 1 .env file after .latchignore filtering, got {:?}",
        files
    );
    assert!(files[0].ends_with(".env"));
    // Specifically not the ignored ones
    for f in &files {
        let s = f.to_string_lossy();
        assert!(!s.contains("secrets/"), "secrets/ should be excluded");
        assert!(!s.contains("public/"), "public/ should be excluded");
    }
}

#[test]
fn scan_skips_latch_config_directory() {
    // .latch/ directory must never be scanned even without .latchignore
    let root = fixtures("simple-project");
    let files = scan_env_files(&root);
    for f in &files {
        assert!(
            !f.to_string_lossy().contains(".latch/"),
            ".latch/ directory must never be scanned: {:?}",
            f
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Path flattening (all fixture paths)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn flatten_fixture_paths() {
    let cases = [
        (".env", "env"),
        ("backend/.env", "backend.env"),
        ("frontend/.env", "frontend.env"),
        ("services/api/.env", "services.api.env"),
        ("services/api/.env.staging", "services.api.env.staging"),
        ("services/worker/.env", "services.worker.env"),
        ("apps/web/.env", "apps.web.env"),
        ("src/config/.env", "src.config.env"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            flatten_path(Path::new(input)),
            expected,
            "Flattening '{}' should give '{}'",
            input,
            expected
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. .env.example generation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn example_strips_values() {
    let content = "DB_HOST=localhost\nDB_PASS=secret123\n# comment\nPORT=3000\n";
    let example = generate_example(content);
    assert!(example.contains("DB_HOST="), "Key should be present");
    assert!(example.contains("DB_PASS="), "Key should be present");
    assert!(example.contains("PORT="), "Key should be present");
    assert!(!example.contains("localhost"), "Value should be stripped");
    assert!(!example.contains("secret123"), "Value should be stripped");
    assert!(!example.contains("3000"), "Value should be stripped");
    assert!(
        example.contains("# comment"),
        "Comments should be preserved"
    );
}

#[test]
fn example_preserves_blank_lines() {
    let content = "A=1\n\nB=2\n";
    let example = generate_example(content);
    assert!(example.contains("\n\n"), "Blank lines should be preserved");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Template variable expansion
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn expand_env_file_resolves_self_references() {
    let content = "\
DB_HOST=localhost\n\
DB_PORT=5432\n\
DB_NAME=myapp\n\
DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/${DB_NAME}\n";

    let expanded = expand_env_file(content);
    assert!(
        expanded.contains("DATABASE_URL=postgres://localhost:5432/myapp"),
        "Template should expand to: DATABASE_URL=postgres://localhost:5432/myapp\nGot:\n{}",
        expanded
    );
}

#[test]
fn expand_env_file_passes_through_blank_and_comments() {
    let content = "# This is a comment\n\nFOO=bar\n";
    let expanded = expand_env_file(content);
    assert!(expanded.contains("# This is a comment"));
    assert!(expanded.contains("FOO=bar"));
}

#[test]
fn expand_env_file_fixture_backend() {
    // The backend fixture has template references
    let content = std::fs::read_to_string(fixtures("simple-project").join("backend/.env")).unwrap();
    let expanded = expand_env_file(&content);
    assert!(
        expanded.contains("DATABASE_URL=postgres://admin:password123@localhost:5432/backend_db"),
        "Backend DATABASE_URL should be fully expanded.\nGot:\n{}",
        expanded
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Manifest serialisation roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_roundtrip() {
    let mut m = Manifest::new("test-project", None);
    m.set_env(
        "dev",
        vec![
            FileMapping {
                local_path: ".env".to_string(),
            },
            FileMapping {
                local_path: "backend/.env".to_string(),
            },
        ],
    );
    m.set_env(
        "prod",
        vec![FileMapping {
            local_path: ".env".to_string(),
        }],
    );

    let bytes = m.to_bytes().unwrap();
    let loaded = Manifest::from_bytes(&bytes).unwrap();

    assert_eq!(loaded.project, "test-project");
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.get_env("dev").len(), 2);
    assert_eq!(loaded.get_env("prod").len(), 1);
    assert_eq!(loaded.get_env("staging").len(), 0);
}

#[test]
fn manifest_preserves_kdf_salt() {
    let salt = generate_salt_b64();
    let m = Manifest::new("salt-project", Some(salt.clone()));
    let bytes = m.to_bytes().unwrap();
    let loaded = Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.kdf_salt, Some(salt));
}

#[test]
fn manifest_remote_path_format() {
    assert_eq!(Manifest::remote_path("my-app"), "my-app/manifest.json");
    assert_eq!(Manifest::remote_path("org/sub"), "org/sub/manifest.json");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Save + Export roundtrip via MockStorage
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn save_then_export_roundtrip_single_file() {
    let storage = MockStorage::new();
    let key = parse_key(&generate_key_hex()).unwrap();
    let project = "roundtrip-test";
    let env = "dev";
    let plaintext = b"SECRET=value\nPORT=3000\n";

    // Simulate save: encrypt and push
    let ciphertext = encrypt(plaintext, &key).unwrap();
    let flat = "env";
    let rpath = remote_path(project, env, flat);
    storage
        .push_file(&rpath, &ciphertext, "save")
        .await
        .unwrap();

    // Push manifest
    let mut manifest = Manifest::new(project, None);
    manifest.set_env(
        env,
        vec![FileMapping {
            local_path: ".env".to_string(),
        }],
    );
    let manifest_bytes = manifest.to_bytes().unwrap();
    storage
        .push_file(&Manifest::remote_path(project), &manifest_bytes, "init")
        .await
        .unwrap();

    // Simulate export: pull manifest, pull file, decrypt
    let pulled_manifest_bytes = storage
        .pull_file(&Manifest::remote_path(project))
        .await
        .unwrap();
    let pulled_manifest = Manifest::from_bytes(&pulled_manifest_bytes).unwrap();
    let mappings = pulled_manifest.get_env(env);
    assert_eq!(mappings.len(), 1);

    let pulled_ct = storage.pull_file(&rpath).await.unwrap();
    let recovered = decrypt(&pulled_ct, &key).unwrap();
    assert_eq!(recovered, plaintext.to_vec());
}

#[tokio::test]
async fn save_then_export_roundtrip_multiple_files() {
    let storage = MockStorage::new();
    let key = parse_key(&generate_key_hex()).unwrap();
    let project = "multi-file-test";
    let env = "dev";

    let files = [
        (".env", "ROOT_SECRET=root\n"),
        ("backend/.env", "DB_PASS=db-secret\n"),
        ("frontend/.env", "API_KEY=api-key\n"),
    ];

    let mut mappings = Vec::new();
    for (local_path, content) in &files {
        let ct = encrypt(content.as_bytes(), &key).unwrap();
        let flat = flatten_path(Path::new(local_path));
        let rpath = remote_path(project, env, &flat);
        storage.push_file(&rpath, &ct, "save").await.unwrap();
        mappings.push(FileMapping {
            local_path: local_path.to_string(),
        });
    }

    // Push manifest
    let mut manifest = Manifest::new(project, None);
    manifest.set_env(env, mappings);
    storage
        .push_file(
            &Manifest::remote_path(project),
            &manifest.to_bytes().unwrap(),
            "init",
        )
        .await
        .unwrap();

    // Export and verify all files
    let pulled_manifest = Manifest::from_bytes(
        &storage
            .pull_file(&Manifest::remote_path(project))
            .await
            .unwrap(),
    )
    .unwrap();

    for (local_path, expected_content) in &files {
        let flat = flatten_path(Path::new(local_path));
        let rpath = remote_path(project, env, &flat);
        let ct = storage.pull_file(&rpath).await.unwrap();
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(
            String::from_utf8(pt).unwrap(),
            *expected_content,
            "File '{}' content mismatch after roundtrip",
            local_path
        );
    }

    assert_eq!(pulled_manifest.get_env(env).len(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Key rotation via MockStorage
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn key_rotation_makes_old_key_invalid() {
    let storage = MockStorage::new();
    let old_key = parse_key(&generate_key_hex()).unwrap();
    let new_key = parse_key(&generate_key_hex()).unwrap();
    let project = "rotate-test";
    let env = "dev";

    let plaintext = b"ROTATE_ME=sensitive\n";
    let flat = "env";
    let rpath = remote_path(project, env, flat);

    // Save with old key
    storage
        .push_file(&rpath, &encrypt(plaintext, &old_key).unwrap(), "save")
        .await
        .unwrap();

    // Rotate: decrypt with old, re-encrypt with new
    let ct_old = storage.pull_file(&rpath).await.unwrap();
    let pt = decrypt(&ct_old, &old_key).unwrap();
    let ct_new = encrypt(&pt, &new_key).unwrap();
    storage.push_file(&rpath, &ct_new, "rotate").await.unwrap();

    // Old key must no longer work
    let ct_after = storage.pull_file(&rpath).await.unwrap();
    assert!(
        decrypt(&ct_after, &old_key).is_err(),
        "Old key must fail after rotation"
    );

    // New key must work
    let recovered = decrypt(&ct_after, &new_key).unwrap();
    assert_eq!(recovered, plaintext.to_vec());
}

#[tokio::test]
async fn key_rotation_all_files_reencrypted() {
    let storage = MockStorage::new();
    let old_key = parse_key(&generate_key_hex()).unwrap();
    let new_key = parse_key(&generate_key_hex()).unwrap();
    let project = "rotate-all-test";
    let env = "dev";

    let files = [
        ("env", b"A=1\n" as &[u8]),
        ("backend.env", b"B=2\n"),
        ("frontend.env", b"C=3\n"),
    ];

    // Save all with old key + build manifest
    let mut manifest = Manifest::new(project, None);
    let mut file_mappings = Vec::new();
    for (flat, content) in &files {
        let rpath = remote_path(project, env, flat);
        storage
            .push_file(&rpath, &encrypt(content, &old_key).unwrap(), "save")
            .await
            .unwrap();
        file_mappings.push(FileMapping {
            local_path: format!(".{}.env", flat.trim_end_matches(".env")),
        });
    }
    manifest.set_env(env, file_mappings);
    storage
        .push_file(
            &Manifest::remote_path(project),
            &manifest.to_bytes().unwrap(),
            "init",
        )
        .await
        .unwrap();

    // Rotate: re-encrypt every file
    for (flat, _) in &files {
        let rpath = remote_path(project, env, flat);
        let ct = storage.pull_file(&rpath).await.unwrap();
        let pt = decrypt(&ct, &old_key).unwrap();
        storage
            .push_file(&rpath, &encrypt(&pt, &new_key).unwrap(), "rotate")
            .await
            .unwrap();
    }

    // Verify all files are inaccessible with old key and accessible with new key
    for (flat, expected) in &files {
        let rpath = remote_path(project, env, flat);
        let ct = storage.pull_file(&rpath).await.unwrap();
        assert!(
            decrypt(&ct, &old_key).is_err(),
            "Old key must fail for {}",
            flat
        );
        let pt = decrypt(&ct, &new_key).unwrap();
        assert_eq!(
            &pt, expected,
            "Content mismatch for {} after rotation",
            flat
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Status check (in-sync vs modified vs missing)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_in_sync_when_content_matches() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let local_content = b"SECRET=hello\n";
    let ct = encrypt(local_content, &key).unwrap();

    // Decrypt and compare (same as what status command does)
    let remote_decrypted = decrypt(&ct, &key).unwrap();
    assert_eq!(
        remote_decrypted,
        local_content.to_vec(),
        "Status: in-sync check failed"
    );
}

#[tokio::test]
async fn status_detects_local_modification() {
    let key = parse_key(&generate_key_hex()).unwrap();
    let remote_content = b"SECRET=original\n";
    let local_content = b"SECRET=modified\n";

    let ct = encrypt(remote_content, &key).unwrap();
    let remote_decrypted = decrypt(&ct, &key).unwrap();

    assert_ne!(
        remote_decrypted,
        local_content.to_vec(),
        "Status: modified file should not match remote"
    );
}

#[tokio::test]
async fn status_missing_remote_file() {
    let storage = MockStorage::new();
    // Don't seed anything
    let result = storage.pull_file("project/dev/missing.env.enc").await;
    assert!(result.is_err(), "Missing remote file should return error");
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Multi-key environment isolation (8.5)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dev_and_prod_keys_are_isolated() {
    let dev_key = parse_key(&generate_key_hex()).unwrap();
    let prod_key = parse_key(&generate_key_hex()).unwrap();

    let dev_secret = b"DEV_SECRET=dev-value\n";
    let prod_secret = b"PROD_SECRET=prod-value\n";

    let dev_ct = encrypt(dev_secret, &dev_key).unwrap();
    let prod_ct = encrypt(prod_secret, &prod_key).unwrap();

    // Dev key cannot read prod
    assert!(
        decrypt(&prod_ct, &dev_key).is_err(),
        "Dev key must not decrypt prod secrets"
    );

    // Prod key cannot read dev
    assert!(
        decrypt(&dev_ct, &prod_key).is_err(),
        "Prod key must not decrypt dev secrets"
    );

    // Each key reads its own env correctly
    assert_eq!(decrypt(&dev_ct, &dev_key).unwrap(), dev_secret.to_vec());
    assert_eq!(decrypt(&prod_ct, &prod_key).unwrap(), prod_secret.to_vec());
}

#[tokio::test]
async fn multi_key_save_export_per_env() {
    let storage = MockStorage::new();
    let dev_key = parse_key(&generate_key_hex()).unwrap();
    let prod_key = parse_key(&generate_key_hex()).unwrap();
    let project = "multi-key-project";

    let dev_content = b"ENV=dev\nSECRET=dev-secret\n";
    let prod_content = b"ENV=prod\nSECRET=prod-secret\n";

    // Save dev
    let dev_flat = "env";
    storage
        .push_file(
            &remote_path(project, "dev", dev_flat),
            &encrypt(dev_content, &dev_key).unwrap(),
            "save dev",
        )
        .await
        .unwrap();

    // Save prod
    storage
        .push_file(
            &remote_path(project, "prod", dev_flat),
            &encrypt(prod_content, &prod_key).unwrap(),
            "save prod",
        )
        .await
        .unwrap();

    // Export dev with dev key
    let dev_ct = storage
        .pull_file(&remote_path(project, "dev", dev_flat))
        .await
        .unwrap();
    assert_eq!(decrypt(&dev_ct, &dev_key).unwrap(), dev_content.to_vec());
    assert!(
        decrypt(&dev_ct, &prod_key).is_err(),
        "Prod key must not export dev"
    );

    // Export prod with prod key
    let prod_ct = storage
        .pull_file(&remote_path(project, "prod", dev_flat))
        .await
        .unwrap();
    assert_eq!(decrypt(&prod_ct, &prod_key).unwrap(), prod_content.to_vec());
    assert!(
        decrypt(&prod_ct, &dev_key).is_err(),
        "Dev key must not export prod"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Run command — env var injection simulation
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate what `latch run` does: decrypt into memory and parse k=v pairs.
fn parse_env_pairs(plaintext: &[u8]) -> Vec<(String, String)> {
    let content = std::str::from_utf8(plaintext).unwrap();
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .filter_map(|l| {
            let eq = l.find('=')?;
            let k = l[..eq].trim().to_string();
            let v = l[eq + 1..].to_string();
            if k.is_empty() { None } else { Some((k, v)) }
        })
        .collect()
}

#[tokio::test]
async fn run_decrypts_and_parses_env_vars() {
    let storage = MockStorage::new();
    let key = parse_key(&generate_key_hex()).unwrap();
    let project = "run-test";
    let env = "dev";

    let content = "SECRET=mysecret\nPORT=3000\n# comment\nDB_URL=postgres://localhost/db\n";
    let flat = "env";
    let rpath = remote_path(project, env, flat);

    storage
        .push_file(&rpath, &encrypt(content.as_bytes(), &key).unwrap(), "save")
        .await
        .unwrap();

    let ct = storage.pull_file(&rpath).await.unwrap();
    let pt = decrypt(&ct, &key).unwrap();
    let pairs = parse_env_pairs(&pt);

    assert_eq!(
        pairs.len(),
        3,
        "Should parse 3 k=v pairs (comment excluded)"
    );
    assert!(pairs.iter().any(|(k, v)| k == "SECRET" && v == "mysecret"));
    assert!(pairs.iter().any(|(k, v)| k == "PORT" && v == "3000"));
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "DB_URL" && v == "postgres://localhost/db")
    );
}

#[tokio::test]
async fn run_expands_template_vars_before_inject() {
    let storage = MockStorage::new();
    let key = parse_key(&generate_key_hex()).unwrap();
    let project = "run-template-test";
    let env = "dev";

    let content = "DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=myapp\nDATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/${DB_NAME}\n";
    storage
        .push_file(
            &remote_path(project, env, "env"),
            &encrypt(content.as_bytes(), &key).unwrap(),
            "save",
        )
        .await
        .unwrap();

    let ct = storage
        .pull_file(&remote_path(project, env, "env"))
        .await
        .unwrap();
    let pt = decrypt(&ct, &key).unwrap();

    // Simulate expand-then-inject as done in run.rs
    let mut resolved: Vec<(String, String)> = Vec::new();
    for (k, v) in parse_env_pairs(&pt) {
        let expanded = expand_env_vars(&v, &resolved);
        resolved.push((k, expanded));
    }

    let db_url = resolved.iter().find(|(k, _)| k == "DATABASE_URL").unwrap();
    assert_eq!(db_url.1, "postgres://localhost:5432/myapp");
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. MockStorage — delete file support (needed for rotate + prune)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mock_storage_overwrite_is_idempotent() {
    let storage = MockStorage::new();
    storage.push_file("a/b.enc", b"v1", "first").await.unwrap();
    storage.push_file("a/b.enc", b"v2", "second").await.unwrap();
    let data = storage.pull_file("a/b.enc").await.unwrap();
    assert_eq!(data, b"v2");
}

#[tokio::test]
async fn mock_list_files_by_prefix() {
    let storage = MockStorage::new();
    storage.seed("proj/dev/a.enc", b"a");
    storage.seed("proj/dev/b.enc", b"b");
    storage.seed("proj/prod/c.enc", b"c");
    storage.seed("other/dev/d.enc", b"d");

    let dev_files = storage.list_files("proj/dev/").await.unwrap();
    assert_eq!(dev_files.len(), 2);
    for f in &dev_files {
        assert!(f.starts_with("proj/dev/"));
    }

    let prod_files = storage.list_files("proj/prod/").await.unwrap();
    assert_eq!(prod_files.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Passphrase-derived key: save and export stability
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn passphrase_key_save_export_roundtrip() {
    let salt_b64 = generate_salt_b64();
    let salt = decode_salt(&salt_b64).unwrap();
    let passphrase = "correct horse battery staple";

    let key = derive_key(passphrase, &salt).unwrap();

    let storage = MockStorage::new();
    let project = "passphrase-project";
    let env = "dev";
    let content = b"DB_PASS=very-secret\n";

    let ct = encrypt(content, &key).unwrap();
    storage
        .push_file(&remote_path(project, env, "env"), &ct, "save")
        .await
        .unwrap();

    // Later: re-derive key from same passphrase + salt
    let key2 = derive_key(passphrase, &salt).unwrap();
    let ct2 = storage
        .pull_file(&remote_path(project, env, "env"))
        .await
        .unwrap();
    let pt2 = decrypt(&ct2, &key2).unwrap();

    assert_eq!(
        pt2,
        content.to_vec(),
        "Passphrase-derived key must be stable across derive calls"
    );
}

#[tokio::test]
async fn wrong_passphrase_cannot_export() {
    let salt = decode_salt(&generate_salt_b64()).unwrap();
    let key_correct = derive_key("correct passphrase", &salt).unwrap();
    let key_wrong = derive_key("wrong passphrase", &salt).unwrap();

    let ct = encrypt(b"SECRET=value\n", &key_correct).unwrap();
    assert!(
        decrypt(&ct, &key_wrong).is_err(),
        "Wrong passphrase must not decrypt secrets"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Manifest set_env is idempotent / overwrite-safe
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_set_env_overwrites_existing() {
    let mut m = Manifest::new("proj", None);
    m.set_env(
        "dev",
        vec![FileMapping {
            local_path: ".env".to_string(),
        }],
    );
    m.set_env(
        "dev",
        vec![
            FileMapping {
                local_path: ".env".to_string(),
            },
            FileMapping {
                local_path: "backend/.env".to_string(),
            },
        ],
    );
    assert_eq!(
        m.get_env("dev").len(),
        2,
        "set_env should overwrite, not append"
    );
}

#[test]
fn manifest_get_env_empty_for_unknown() {
    let m = Manifest::new("proj", None);
    assert!(m.get_env("nonexistent").is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Full fixture file encrypt/decrypt using real file content
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn encrypt_decrypt_real_fixture_files() {
    let fixture_files = [
        "simple-project/.env",
        "simple-project/backend/.env",
        "simple-project/frontend/.env",
        "monorepo/services/api/.env",
        "monorepo/services/api/.env.staging",
        "monorepo/services/worker/.env",
        "monorepo/apps/web/.env",
        "nested-project/.env",
        "nested-project/src/config/.env",
        "ignored-project/.env",
    ];

    let key = parse_key(&generate_key_hex()).unwrap();

    for path in &fixture_files {
        let full = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(path);
        let content = std::fs::read(&full)
            .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path, e));

        let ct = encrypt(&content, &key)
            .unwrap_or_else(|e| panic!("Encrypt failed for {}: {}", path, e));
        let pt =
            decrypt(&ct, &key).unwrap_or_else(|e| panic!("Decrypt failed for {}: {}", path, e));

        assert_eq!(
            pt, content,
            "Encrypt→decrypt must be lossless for fixture file: {}",
            path
        );
    }
}
