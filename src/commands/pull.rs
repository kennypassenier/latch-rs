use anyhow::Result;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::{env, path::Path};

use crate::{
    config::project::ProjectConfig,
    credentials::FallbackChain,
    crypto::{decrypt, parse_key},
    discovery::{flatten_path, local_blob_path, remote_path},
    github::{RemoteStorage as _, client::GitHubClient},
    manifest::Manifest,
};

#[derive(Debug, Clone)]
pub struct PullArgs {
    pub env: String,
    pub pat: Option<String>,
    pub key: Option<String>,
    pub repo: Option<String>,
    pub project: Option<String>,
    pub dry_run: bool,
    pub sparse: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullContext {
    project: String,
    secrets_repo: String,
    project_root: std::path::PathBuf,
    pat: String,
    key: Option<String>,
}

pub async fn run(args: PullArgs) -> Result<()> {
    let cwd = env::current_dir()?;
    let ctx = resolve_pull_context(&cwd, &args)?;
    let env_name = args.env.as_str();

    let chain = FallbackChain::new(&ctx.project);
    let pat = ctx.pat;

    let github = GitHubClient::new(&ctx.secrets_repo, &pat)?;

    let manifest_path = Manifest::remote_path(&ctx.project);
    let manifest_bytes = github.pull_file(&manifest_path).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to read '{}' from {}: {}\n\
             This usually means one of:\n\
             - PAT is invalid or lacks access to the repo\n\
             - project/repo is wrong\n\
             - manifest is genuinely missing (run 'latch init' + 'latch push' on the source machine).",
            manifest_path,
            ctx.secrets_repo,
            e
        )
    })?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let mappings = manifest.get_env(env_name);
    let has_legacy_groups = manifest.clone_groups.iter().any(|g| g.env == env_name);

    if mappings.is_empty() {
        if has_legacy_groups {
            anyhow::bail!(
                "Clone groups are temporarily disabled.\n\
                 This env currently has only group-based entries in the manifest.\n\
                 Re-stage on the source machine with: 'latch commit --env {} && latch push --env {} --force'",
                env_name,
                env_name
            );
        }
        println!(
            "No files tracked for env '{}' in project '{}'. Run 'latch push --env {}' first.",
            env_name, ctx.project, env_name
        );
        return Ok(());
    }

    if has_legacy_groups {
        println!(
            "Note: clone groups are temporarily disabled in this version; only standalone file mappings are pulled."
        );
    }

    if args.dry_run {
        let mode = if args.sparse { "sparse" } else { "full" };
        println!(
            "[dry-run][{}] Would pull {} standalone file(s) for env '{}' into {}",
            mode,
            mappings.len(),
            env_name,
            ctx.project_root.display()
        );
        for m in mappings {
            let rel = &m.local_path;
            let flat = flatten_path(Path::new(rel));
            let remote = remote_path(&ctx.project, env_name, &flat);
            let local_abs = ctx.project_root.join(rel);
            if should_skip_for_sparse(&local_abs, args.sparse) {
                println!("  {} <- {} [skip: parent directory missing]", rel, remote);
            } else {
                println!("  {} <- {}", rel, remote);
            }
        }
        return Ok(());
    }

    let (primary_source, key_hex) = match ctx.key {
        Some(key) => ("arg:--KEY".to_string(), key),
        None => (
            "resolved:keychain".to_string(),
            chain.get_key_for_env(Some(env_name))?,
        ),
    };

    let total = mappings.len();

    // Resolve the effective decryption key by probing known candidates against the
    // first available ciphertext. This prevents stale-source precedence issues.
    let mut first_probe_target: Option<String> = None;
    let mut first_probe_ciphertext: Option<Vec<u8>> = None;
    if let Some(first) = mappings.first() {
        let flat = flatten_path(Path::new(&first.local_path));
        let remote = remote_path(&ctx.project, env_name, &flat);
        first_probe_ciphertext = Some(github.pull_file(&remote).await?);
        first_probe_target = Some(remote);
    }

    let candidates = key_candidates(&chain, Some(env_name), &key_hex, &primary_source);
    if candidates.is_empty() {
        anyhow::bail!(
            "No encryption key found for env '{}' in project '{}'.",
            env_name,
            ctx.project
        );
    }

    let probe_blob = first_probe_ciphertext
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No ciphertext available to validate decryption key."))?;

    let mut parsed_candidates: Vec<(String, [u8; 32])> = Vec::new();
    let mut chosen_key: Option<[u8; 32]> = None;
    let mut chosen_source: Option<String> = None;
    let mut attempted: Vec<String> = Vec::new();

    for (source, candidate_raw) in candidates {
        let parsed = match parse_key(&candidate_raw) {
            Ok(k) => k,
            Err(_) => {
                attempted.push(format!("{} (invalid-format)", source));
                continue;
            }
        };

        parsed_candidates.push((source.clone(), parsed));

        if decrypt(probe_blob, &parsed).is_ok() {
            chosen_key = Some(parsed);
            chosen_source = Some(source.clone());
            break;
        }

        attempted.push(format!("{} ({})", source, key_fingerprint(&parsed)));
    }

    let key = chosen_key.ok_or_else(|| {
        anyhow::anyhow!(
            "Decryption failed for all known keys while validating '{}'. Tried: {}",
            first_probe_target
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string()),
            attempted.join(", ")
        )
    })?;

    let key_source = chosen_source.unwrap_or_else(|| "unknown".to_string());
    let key_fp = key_fingerprint(&key);
    println!("Using decryption key from {} ({})", key_source, key_fp);

    println!(
        "Pulling {} file(s) for env '{}' from {} -> {}",
        total,
        env_name,
        ctx.secrets_repo,
        ctx.project_root.display()
    );
    if args.sparse {
        println!("Sparse mode enabled: only existing directories will receive .env files.");
    }

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
        )?
        .progress_chars("=> "),
    );

    let mut written = 0usize;
    let mut skipped = 0usize;

    macro_rules! write_file {
        ($local_abs:expr, $plaintext:expr) => {{
            let local_abs: &std::path::Path = $local_abs;
            let plaintext: &[u8] = $plaintext;
            let mut do_write = true;
            if local_abs.exists() {
                let existing = std::fs::read(local_abs)?;
                if existing != plaintext {
                    pb.suspend(|| {
                        println!(
                            "\n  {} already exists and differs from the remote version.",
                            local_abs.display()
                        );
                    });
                    let overwrite = pb.suspend(|| {
                        Confirm::new()
                            .with_prompt(format!("  Overwrite {}?", local_abs.display()))
                            .default(false)
                            .interact()
                    });
                    match overwrite {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            do_write = false;
                        }
                    }
                }
            }
            if do_write {
                if let Some(parent) = local_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(local_abs, plaintext)?;
                written += 1;
            } else {
                skipped += 1;
            }
            pb.inc(1);
        }};
    }

    for mapping in mappings {
        let rel_path = Path::new(&mapping.local_path);
        let flat = flatten_path(rel_path);
        let remote = remote_path(&ctx.project, env_name, &flat);
        let local_abs = ctx.project_root.join(rel_path);

        pb.set_message(format!("{}", rel_path.display()));

        let ciphertext = if first_probe_target.as_deref() == Some(remote.as_str()) {
            first_probe_ciphertext.clone().unwrap_or_default()
        } else {
            github.pull_file(&remote).await?
        };
        // Cache encrypted blob to .latch/ for offline commit and subscribe-intent.
        let cached = local_blob_path(&ctx.project_root, env_name, &flat);
        if let Some(p) = cached.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cached, &ciphertext)?;
        let plaintext =
            decrypt_with_candidates(&ciphertext, &remote, &key, &key_source, &parsed_candidates)?;
        if should_skip_for_sparse(&local_abs, args.sparse) {
            pb.suspend(|| {
                println!(
                    "  skipping {} (parent directory missing)",
                    local_abs.display()
                );
            });
            skipped += 1;
            pb.inc(1);
            continue;
        }
        write_file!(&local_abs, &plaintext);
    }

    pb.finish_with_message("Pull complete");
    println!("\nPulled {} file(s), skipped {}.", written, skipped);

    // Update the local staging cache so `latch commit` can work offline
    // and subscribe-intent clone-group members can resolve from the cache.
    manifest.save_staging(&ctx.project_root)?;
    Ok(())
}

fn resolve_pull_context(cwd: &Path, args: &PullArgs) -> Result<PullContext> {
    let local_cfg = ProjectConfig::find_and_load(cwd).ok();

    let project = match args.project.as_deref() {
        Some(project) => project.to_string(),
        None => local_cfg
            .as_ref()
            .map(|(cfg, _)| cfg.name.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No .latch/config.toml found. Provide --project for a one-shot pull."
                )
            })?,
    };

    let secrets_repo = match args.repo.as_deref() {
        Some(repo) => repo.to_string(),
        None => local_cfg
            .as_ref()
            .map(|(cfg, _)| cfg.secrets_repo.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No .latch/config.toml found. Provide --REPO owner/repo for a one-shot pull."
                )
            })?,
    };

    let project_root = local_cfg
        .as_ref()
        .map(|(_, root)| root.clone())
        .unwrap_or_else(|| cwd.to_path_buf());

    let pat = match args.pat.as_deref() {
        Some(pat) => pat.to_string(),
        None => FallbackChain::new(&project).get_pat()?,
    };

    if local_cfg.is_none() && args.key.is_none() {
        anyhow::bail!(
            "No .latch/config.toml found. Provide --KEY for a one-shot pull when running without project metadata."
        );
    }

    Ok(PullContext {
        project,
        secrets_repo,
        project_root,
        pat,
        key: args.key.clone(),
    })
}

fn key_candidates(
    chain: &FallbackChain,
    env: Option<&str>,
    explicit_key: &str,
    primary_source: &str,
) -> Vec<(String, String)> {
    let mut candidates = vec![(primary_source.to_string(), explicit_key.to_string())];
    for (source, candidate) in chain.key_candidates_for_env(env) {
        if candidate != explicit_key {
            candidates.push((source, candidate));
        }
    }
    candidates
}

fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("fp:{}", hex::encode(&digest[..6]))
}

fn decrypt_with_candidates(
    ciphertext: &[u8],
    remote_path: &str,
    primary_key: &[u8; 32],
    primary_source: &str,
    candidates: &[(String, [u8; 32])],
) -> Result<Vec<u8>> {
    if let Ok(plaintext) = decrypt(ciphertext, primary_key) {
        return Ok(plaintext);
    }

    for (source, key) in candidates {
        if source == primary_source {
            continue;
        }
        if let Ok(plaintext) = decrypt(ciphertext, key) {
            return Ok(plaintext);
        }
    }

    let tried = std::iter::once(format!(
        "{} ({})",
        primary_source,
        key_fingerprint(primary_key)
    ))
    .chain(
        candidates
            .iter()
            .filter(|(source, _)| source != primary_source)
            .map(|(source, key)| format!("{} ({})", source, key_fingerprint(key))),
    )
    .collect::<Vec<_>>()
    .join(", ");

    anyhow::bail!(
        "Failed to decrypt remote blob '{}' with all known keys. Tried: {}",
        remote_path,
        tried
    )
}

fn should_skip_for_sparse(local_abs: &Path, sparse: bool) -> bool {
    if !sparse {
        return false;
    }

    match local_abs.parent() {
        Some(parent) => !parent.exists(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{PullArgs, key_candidates, resolve_pull_context};
    use crate::config::project::ProjectConfig;
    use crate::credentials::FallbackChain;
    use tempfile::TempDir;

    fn base_args() -> PullArgs {
        PullArgs {
            env: "dev".to_string(),
            pat: None,
            key: None,
            repo: None,
            project: None,
            dry_run: false,
            sparse: false,
        }
    }

    #[test]
    fn one_shot_pull_uses_current_directory_without_local_config() {
        let tmp = TempDir::new().expect("temp dir");
        let args = PullArgs {
            pat: Some("pat123".to_string()),
            key: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            ),
            repo: Some("owner/secrets".to_string()),
            project: Some("demo".to_string()),
            ..base_args()
        };

        let ctx = resolve_pull_context(tmp.path(), &args).expect("one-shot context");

        assert_eq!(ctx.project, "demo");
        assert_eq!(ctx.secrets_repo, "owner/secrets");
        assert_eq!(ctx.project_root, tmp.path());
        assert_eq!(ctx.pat, "pat123");
        assert_eq!(
            ctx.key.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
    }

    #[test]
    fn one_shot_pull_requires_project_and_repo_without_local_config() {
        let tmp = TempDir::new().expect("temp dir");
        let err = resolve_pull_context(tmp.path(), &base_args()).expect_err("missing args");
        let msg = err.to_string();

        assert!(msg.contains("--project") || msg.contains("--REPO"));
    }

    #[test]
    fn local_project_config_still_works_without_explicit_overrides() {
        let tmp = TempDir::new().expect("temp dir");
        ProjectConfig {
            name: "demo".to_string(),
            secrets_repo: "owner/secrets".to_string(),
            default_env: "dev".to_string(),
        }
        .save_in(tmp.path())
        .expect("save config");

        // Resolve context using local config without explicit PAT/key/repo args.
        // The PAT should be resolved from the fallback chain (env, keyring, global config).
        let ctx = resolve_pull_context(tmp.path(), &base_args()).expect("config context");

        assert_eq!(ctx.project, "demo");
        assert_eq!(ctx.secrets_repo, "owner/secrets");
        assert_eq!(ctx.project_root, tmp.path());
        assert!(!ctx.pat.is_empty()); // Verify PAT was resolved from fallback chain
        assert!(ctx.key.is_none()); // Key not provided via args
    }

    #[test]
    fn explicit_key_stays_first_in_candidate_order() {
        let chain = FallbackChain::new("demo");
        let explicit = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let candidates = key_candidates(&chain, Some("dev"), explicit, "arg:--KEY");

        assert_eq!(candidates[0].0, "arg:--KEY");
        assert_eq!(candidates[0].1, explicit);
    }
}
