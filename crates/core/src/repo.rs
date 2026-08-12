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

/// What `refresh` actually did — so callers never claim "fresh" while
/// serving stale content (D1b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// Could not reach the remote; the cached clone is being used (S5).
    Offline,
    /// The clone now reflects the remote (reset, or already up to date).
    Current,
    /// Reached the remote, but kept local work (dirty or unpushed commits)
    /// — the clone does NOT reflect the remote yet.
    Diverged,
}

impl RefreshState {
    /// Did we contact the remote at all?
    pub fn reached_remote(&self) -> bool {
        !matches!(self, RefreshState::Offline)
    }
    /// Does the clone now faithfully reflect the remote?
    pub fn is_current(&self) -> bool {
        matches!(self, RefreshState::Current)
    }
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
    pub fn refresh(&self, require_fresh: bool) -> Result<RefreshState, LatchError> {
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
            return Ok(RefreshState::Offline);
        }
        let has_remote = self
            .git_in(&["rev-parse", "--verify", &format!("origin/{}", BRANCH)])?
            .status
            == 0;
        if !has_remote {
            // Empty remote: nothing to take in; our clone IS current.
            return Ok(RefreshState::Current);
        }
        // NEVER reset over local work that the remote hasn't seen. Two
        // kinds: a dirty tree (staged ciphertexts from `latch commit`
        // awaiting push) OR committed-but-unpushed commits (D1a — a
        // git-committed push that got rejected; a plain porcelain check
        // sees a CLEAN tree and used to hard-reset the commit away). Data
        // preservation beats freshness.
        let dirty = !self.git_in(&["status", "--porcelain"])?.stdout.is_empty();
        let ahead = {
            let out = self.git_in(&["rev-list", "--count", &format!("origin/{}..HEAD", BRANCH)])?;
            String::from_utf8_lossy(&out.stdout).trim() != "0"
        };
        if dirty || ahead {
            // D1b: we did reach the remote but are NOT reflecting it —
            // callers must not report this as a clean fresh pull.
            return Ok(RefreshState::Diverged);
        }
        let out = self.git_in(&["reset", "--hard", &format!("origin/{}", BRANCH), "--quiet"])?;
        self.ok(
            out,
            "update local clone",
            "remove ~/.latch/repo and pull again",
        )?;
        Ok(RefreshState::Current)
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
                    // B2: after reset --soft the index holds the REMOTE
                    // tree but our working tree is stale, so `add -A` would
                    // stage every file another machine added (and we never
                    // pulled) as a DELETION — silently destroying it on
                    // force. checkout-index -a writes index entries that
                    // are MISSING from the working tree back into it,
                    // WITHOUT overwriting the files we actually changed —
                    // so force means "my content wins, everyone else's is
                    // preserved", never "my stale view deletes theirs".
                    let out = self.git_in(&["checkout-index", "-a"])?;
                    self.ok(
                        out,
                        "restore remote-only files before force",
                        "remove ~/.latch/repo and retry",
                    )?;
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

    /// Fetch from origin without touching the working tree (B4: peek at
    /// what the remote holds before deciding whether a push conflicts).
    pub fn fetch(&self) -> Result<bool, LatchError> {
        Ok(self.git_in(&["fetch", "--quiet", "origin"])?.status == 0)
    }

    /// Read a file as it exists at `origin/main` (None = absent there).
    /// Requires a prior `fetch`. Bytes come straight from git's object
    /// store, so the local working tree is never disturbed.
    pub fn read_remote(&self, rel: &str) -> Result<Option<Vec<u8>>, LatchError> {
        self.read_at(&format!("origin/{}", BRANCH), rel)
    }

    /// Read a file at an arbitrary git reference (None = absent there).
    pub fn read_at(&self, reference: &str, rel: &str) -> Result<Option<Vec<u8>>, LatchError> {
        let out = self.git_in(&["show", &format!("{}:{}", reference, rel)])?;
        if out.status != 0 {
            return Ok(None);
        }
        Ok(Some(out.stdout))
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
