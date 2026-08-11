//! The storage backend (AR2): a hidden local git clone of the secrets
//! repository, driven through the real `git` binary. Push and pull are
//! real git operations; overwrite protection (S4) is git's own
//! non-fast-forward refusal; history (S3) and the offline cache (S5) are
//! the clone itself.
//!
//! Authentication travels via GIT_CONFIG_* environment variables — the
//! token never appears in argv. URLs without a scheme are treated as
//! GitHub owner/name; full URLs (https://, file://) pass through, which is
//! also how the end-to-end tests run against a local bare repo with the
//! real git binary.

use crate::error::LatchError;
use crate::platform::Platform;

pub const REPO_DIR: &str = "repo";
const BRANCH: &str = "main";

pub struct Repo<'a> {
    p: &'a Platform<'a>,
    url: String,
    pat: Option<String>,
}

#[derive(Debug)]
pub enum PushOutcome {
    Pushed,
    NothingToPush,
}

impl<'a> Repo<'a> {
    pub fn new(p: &'a Platform<'a>, repo: &str, pat: Option<String>) -> Self {
        let url = if repo.contains("://") {
            repo.to_string()
        } else {
            format!("https://github.com/{}.git", repo)
        };
        Self { p, url, pat }
    }

    pub fn dir(&self) -> String {
        format!("{}/{}", self.p.latch_home, REPO_DIR)
    }

    fn auth_envs(&self) -> Vec<(String, String)> {
        let mut envs = vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];
        if let Some(pat) = &self.pat {
            envs.push(("GIT_CONFIG_COUNT".into(), "1".into()));
            envs.push(("GIT_CONFIG_KEY_0".into(), "http.extraHeader".into()));
            envs.push((
                "GIT_CONFIG_VALUE_0".into(),
                format!(
                    "Authorization: Basic {}",
                    crate::ops::login::base64_basic("x-access-token", pat)
                ),
            ));
        }
        envs
    }

    fn git(&self, args: &[&str]) -> Result<crate::platform::ProcOutput, LatchError> {
        let envs = self.auth_envs();
        let env_refs: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.p.proc.run("git", args, &env_refs, None)
    }

    fn git_in(&self, args: &[&str]) -> Result<crate::platform::ProcOutput, LatchError> {
        let dir = self.dir();
        let mut full = vec!["-C", dir.as_str()];
        full.extend_from_slice(args);
        let envs = self.auth_envs();
        let env_refs: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.p.proc.run("git", &full, &env_refs, None)
    }

    fn ok(
        &self,
        out: crate::platform::ProcOutput,
        what: &str,
        remedy: &str,
    ) -> Result<crate::platform::ProcOutput, LatchError> {
        if out.status != 0 {
            return Err(LatchError::other(
                format!("{}: {}", what, String::from_utf8_lossy(&out.stderr).trim()),
                remedy,
            ));
        }
        Ok(out)
    }

    /// Make sure the local clone exists (cloning on first use). An empty
    /// remote is fine — the clone is initialized with the branch ready.
    pub fn ensure(&self) -> Result<(), LatchError> {
        if self
            .p
            .files
            .read(&format!("{}/.git/HEAD", self.dir()))?
            .is_some()
        {
            return Ok(());
        }
        let dir = self.dir();
        let out = self.git(&["clone", "--quiet", &self.url, &dir])?;
        self.ok(
            out,
            "clone secrets repository",
            "check the repo name/URL and your token (latch login re-validates)",
        )?;
        // Empty repo: create the branch so later commits have a home.
        let head = self.git_in(&["rev-parse", "--verify", "HEAD"])?;
        if head.status != 0 {
            let out = self.git_in(&["checkout", "-b", BRANCH])?;
            self.ok(out, "initialize branch", "remove ~/.latch/repo and retry")?;
        }
        Ok(())
    }

    /// Refresh the clone from the remote: fetch + hard reset (the clone is
    /// entirely latch-managed; nobody edits it by hand). Offline (fetch
    /// fails) is only an error when `require_fresh`.
    pub fn refresh(&self, require_fresh: bool) -> Result<bool, LatchError> {
        let fetch = self.git_in(&["fetch", "--quiet", "origin"])?;
        if fetch.status != 0 {
            if require_fresh {
                return Err(LatchError::other(
                    format!(
                        "cannot reach the secrets repository: {}",
                        String::from_utf8_lossy(&fetch.stderr).trim()
                    ),
                    "check your network; for offline use, commands that read can run on the cached clone (S5)",
                ));
            }
            return Ok(false);
        }
        let has_remote = self
            .git_in(&["rev-parse", "--verify", &format!("origin/{}", BRANCH)])?
            .status
            == 0;
        if has_remote {
            let out =
                self.git_in(&["reset", "--hard", &format!("origin/{}", BRANCH), "--quiet"])?;
            self.ok(
                out,
                "update local clone",
                "remove ~/.latch/repo and pull again",
            )?;
        }
        Ok(true)
    }

    /// Stage everything and commit+push (W3) with S4 protection: if the
    /// remote moved past our base, git refuses the push and we surface it.
    /// `force` means "my content wins": we re-commit our tree ON TOP of
    /// the fetched remote head — history is preserved, nothing is ever
    /// force-pushed.
    pub fn push(&self, message: &str, force: bool) -> Result<PushOutcome, LatchError> {
        let status = self.git_in(&["status", "--porcelain"])?;
        if status.stdout.is_empty() {
            return Ok(PushOutcome::NothingToPush);
        }
        if force {
            // Adopt the remote head as parent, keeping our working tree.
            let fetch = self.git_in(&["fetch", "--quiet", "origin"])?;
            if fetch.status == 0 {
                let has_remote = self
                    .git_in(&["rev-parse", "--verify", &format!("origin/{}", BRANCH)])?
                    .status
                    == 0;
                if has_remote {
                    let out = self.git_in(&["reset", "--soft", &format!("origin/{}", BRANCH)])?;
                    self.ok(out, "rebase onto remote", "remove ~/.latch/repo and retry")?;
                }
            }
        }
        let out = self.git_in(&["add", "-A"])?;
        self.ok(out, "stage changes", "check ~/.latch/repo permissions")?;
        let out = self.git_in(&[
            "-c",
            "user.email=latch@local",
            "-c",
            "user.name=latch",
            "commit",
            "--quiet",
            "-m",
            message,
        ])?;
        self.ok(
            out,
            "commit",
            "check ~/.latch/repo state (latch reset rebuilds it)",
        )?;
        let out = self.git_in(&["push", "--quiet", "-u", "origin", BRANCH])?;
        if out.status != 0 {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("non-fast-forward")
                || stderr.contains("fetch first")
                || stderr.contains("rejected")
            {
                return Err(LatchError::other(
                    "the remote has newer changes than your base (S4)",
                    "run 'latch pull' first to take them in, or 'latch push --force' to make YOUR content the newest version (history is kept either way)",
                ));
            }
            return Err(LatchError::other(
                format!("push failed: {}", stderr.trim()),
                "check your network and token, then retry",
            ));
        }
        Ok(PushOutcome::Pushed)
    }

    /// Read a file from the clone (None = absent).
    pub fn read(&self, rel: &str) -> Result<Option<Vec<u8>>, LatchError> {
        self.p.files.read(&format!("{}/{}", self.dir(), rel))
    }

    /// Write a file into the clone working tree (atomic).
    pub fn write(&self, rel: &str, content: &[u8]) -> Result<(), LatchError> {
        self.p
            .files
            .write_atomic(&format!("{}/{}", self.dir(), rel), content)
    }

    /// S3 history: log for a path, `ref|unix|message` per line.
    pub fn git_log(&self, path: &str) -> Result<String, LatchError> {
        let out = self.git_in(&["log", "--pretty=format:%h|%ct|%s", "--", path])?;
        let out = self.ok(
            out,
            "read history",
            "is the clone initialized? (latch status)",
        )?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// S3 rollback: restore `path` to its content at `reference` in the
    /// working tree (validated first so a typo'd ref is a clean error).
    pub fn checkout_path(&self, reference: &str, path: &str) -> Result<(), LatchError> {
        let check = self.git_in(&[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", reference),
        ])?;
        if check.status != 0 {
            return Err(LatchError::other(
                format!("'{}' is not a known version", reference),
                "pick a ref from 'latch history'",
            ));
        }
        let out = self.git_in(&["checkout", reference, "--", path])?;
        self.ok(
            out,
            "restore old version",
            "check the ref and path (latch history)",
        )?;
        Ok(())
    }

    /// Remove a file from the clone working tree.
    pub fn remove(&self, rel: &str) -> Result<(), LatchError> {
        self.p.files.remove(&format!("{}/{}", self.dir(), rel))
    }

    /// List files under a prefix in the clone (relative to the prefix).
    pub fn list(&self, prefix: &str) -> Result<Vec<String>, LatchError> {
        self.p
            .files
            .walk(&format!("{}/{}", self.dir(), prefix))
            .map(|v| v.into_iter().filter(|f| !f.starts_with(".git/")).collect())
    }
}
