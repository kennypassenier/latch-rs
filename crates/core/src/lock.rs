//! The mutation lock (AR12): one latch process mutates at a time. A lock
//! file created exclusively; waiting is bounded and loud; a stale lock
//! (older than STALE_SECS) is broken with a notice — a crashed process
//! must not wedge the tool forever.
//!
//! B3: the lock file carries a per-acquisition random TOKEN. A guard only
//! removes the lock if it still holds that token, so a process whose lock
//! was stale-broken and re-created by ANOTHER process cannot delete the
//! new owner's lock on the way out — the bug that allowed two (or three)
//! concurrent mutators. Interactive `$EDITOR` sessions must NOT hold this
//! lock across the edit (see ops::edit_diff), so the 15-minute stale
//! window is never hit by a legitimately slow operation.

use crate::error::LatchError;
use crate::platform::Platform;

pub const LOCK_FILE: &str = "lock";
pub const STALE_SECS: u64 = 15 * 60;

pub struct LockGuard<'a> {
    p: &'a Platform<'a>,
    path: String,
    token: String,
}

impl std::fmt::Debug for LockGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LockGuard({})", self.path)
    }
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        // Only remove the lock if WE still own it: a stale-break may have
        // handed it to another process, whose lock we must not delete.
        match self.p.files.read(&self.path) {
            Ok(Some(content)) if content == self.token.as_bytes() => {
                let _ = self.p.files.remove(&self.path);
            }
            _ => {}
        }
    }
}

fn new_token() -> String {
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    // Bind the token to this process too, so it is unique even in the
    // (impossible-here) event of an RNG repeat.
    format!("{}-{}", std::process::id(), hex::encode(buf))
}

/// Acquire the mutation lock, polling up to `wait_secs` (whole-second
/// granularity via the injected clock; the real CLI sleeps between polls).
pub fn acquire<'a>(
    p: &'a Platform<'a>,
    wait_secs: u64,
    mut on_wait: impl FnMut(),
) -> Result<LockGuard<'a>, LatchError> {
    let path = format!("{}/{}", p.latch_home, LOCK_FILE);
    let token = new_token();
    let start = p.clock.now_unix();
    loop {
        if p.files.try_create_exclusive(&path, token.as_bytes())? {
            return Ok(LockGuard { p, path, token });
        }
        // Stale lock? Break it once, loudly.
        if let Some(mtime) = p.files.mtime_unix(&path)? {
            if p.clock.now_unix().saturating_sub(mtime) > STALE_SECS {
                p.files.remove(&path)?;
                continue;
            }
        }
        if p.clock.now_unix().saturating_sub(start) >= wait_secs {
            return Err(LatchError::other(
                "another latch operation is running",
                "wait for it to finish, or remove ~/.latch/lock if you are sure none is (a crashed one goes stale after 15 min)",
            ));
        }
        on_wait();
    }
}
