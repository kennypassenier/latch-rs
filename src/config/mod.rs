pub mod global;
pub mod project;

use std::path::PathBuf;

/// Returns `~/.latch/`
pub fn latch_home() -> PathBuf {
    dirs::home_dir()
        .expect("Cannot determine home directory")
        .join(".latch")
}
