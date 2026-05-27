use latch_rs::config::project::ProjectConfig;
use latch_rs::discovery::{flatten_path, generate_example, scan_env_files};
use latch_rs::manifest::Manifest;
/// Configuration and discovery tests
use std::path::Path;
use tempfile::TempDir;

// ── Project config walk-up ────────────────────────────────────────────────────

#[test]
fn finds_config_in_parent_directory() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    // Write .latch/config.toml at root
    let cfg = ProjectConfig {
        name: "testapp".to_string(),
        secrets_repo: "owner/repo".to_string(),
        default_env: "dev".to_string(),
    };
    cfg.save_in(root).unwrap();

    // Start search from a nested subdirectory
    let nested = root.join("src").join("backend");
    std::fs::create_dir_all(&nested).unwrap();

    let (found, found_root) = ProjectConfig::find_and_load(&nested).unwrap();
    assert_eq!(found.name, "testapp");
    assert_eq!(found_root, root);
}

#[test]
fn errors_when_no_config_found() {
    let tmp = TempDir::new().unwrap();
    let result = ProjectConfig::find_and_load(tmp.path());
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("latch init") || msg.contains(".latch/config.toml"));
}

// ── Discovery ─────────────────────────────────────────────────────────────────

#[test]
fn scanner_finds_env_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::write(root.join(".env"), "KEY=val").unwrap();
    std::fs::create_dir_all(root.join("backend")).unwrap();
    std::fs::write(root.join("backend/.env"), "DB=postgres").unwrap();
    std::fs::write(root.join("backend/.env.local"), "DEBUG=true").unwrap();
    // A non-.env file that should NOT be picked up
    std::fs::write(root.join("backend/app.rs"), "fn main() {}").unwrap();

    let found = scan_env_files(root);
    assert_eq!(found.len(), 3, "Expected 3 .env files, got {:?}", found);
}

#[test]
fn scanner_respects_latchignore() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::write(root.join(".env"), "KEEP=yes").unwrap();
    std::fs::create_dir_all(root.join("ignored_dir")).unwrap();
    std::fs::write(root.join("ignored_dir/.env"), "IGNORE=yes").unwrap();
    std::fs::write(root.join(".latchignore"), "ignored_dir/\n").unwrap();

    let found = scan_env_files(root);
    assert_eq!(found.len(), 1);
    assert!(found[0].ends_with(".env"));
    assert!(!found[0].to_string_lossy().contains("ignored_dir"));
}

// ── Path flattening ───────────────────────────────────────────────────────────

#[test]
fn flatten_single_level() {
    assert_eq!(flatten_path(Path::new("backend/.env")), "backend.env");
}

#[test]
fn flatten_multi_level() {
    assert_eq!(
        flatten_path(Path::new("src/api/service/.env")),
        "src.api.service.env"
    );
}

#[test]
fn flatten_env_variant() {
    assert_eq!(
        flatten_path(Path::new("frontend/.env.local")),
        "frontend.env.local"
    );
}

#[test]
fn flatten_root_env() {
    assert_eq!(flatten_path(Path::new(".env")), "env");
}

// ── .env.example generation ───────────────────────────────────────────────────

#[test]
fn example_strips_values_and_preserves_comments() {
    let input = "# Database\nDB_URL=postgres://secret\n\nPORT=3000\n# End";
    let output = generate_example(input);
    assert!(output.contains("# Database"));
    assert!(output.contains("DB_URL=\n"));
    assert!(output.contains("PORT=\n"));
    assert!(!output.contains("postgres://secret"));
    assert!(!output.contains("3000"));
}

// ── Manifest serialization ────────────────────────────────────────────────────

#[test]
fn manifest_roundtrip() {
    use latch_rs::manifest::FileMapping;
    let mut m = Manifest::new("myapp", Some("abc123==".to_string()));
    m.set_env(
        "dev",
        vec![
            FileMapping {
                local_path: "backend/.env".to_string(),
            },
            FileMapping {
                local_path: "frontend/.env".to_string(),
            },
        ],
    );

    let bytes = m.to_bytes().unwrap();
    let restored = Manifest::from_bytes(&bytes).unwrap();

    assert_eq!(restored.project, "myapp");
    assert_eq!(restored.kdf_salt, Some("abc123==".to_string()));
    assert_eq!(restored.get_env("dev").len(), 2);
    assert_eq!(restored.get_env("prod").len(), 0);
}
