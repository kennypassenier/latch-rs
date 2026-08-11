//! The mutation lock (AR12): one latch process mutates at a time. A lock
//! file created exclusively; waiting is bounded and loud; a stale lock
//! (older than STALE_SECS) is broken with a notice — a crashed process
//! must not wedge the tool forever.

use crate::error::LatchError;
use crate::platform::Platform;

pub const LOCK_FILE: &str = "lock";
pub const STALE_SECS: u64 = 15 * 60;

pub struct LockGuard<'a> {
    p: &'a Platform<'a>,
    path: String,
}

impl std::fmt::Debug for LockGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LockGuard({})", self.path)
    }
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        let _ = self.p.files.remove(&self.path);
    }
}

/// Acquire the mutation lock, polling up to `wait_secs` (whole-second
/// granularity via the injected clock; the real CLI sleeps between polls).
pub fn acquire<'a>(
    p: &'a Platform<'a>,
    wait_secs: u64,
    mut on_wait: impl FnMut(),
) -> Result<LockGuard<'a>, LatchError> {
    let path = format!("{}/{}", p.latch_home, LOCK_FILE);
    let start = p.clock.now_unix();
    loop {
        if p.files.try_create_exclusive(&path, b"latch")? {
            return Ok(LockGuard { p, path });
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
