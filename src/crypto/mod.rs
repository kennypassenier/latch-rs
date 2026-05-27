pub mod key;
pub use key::{SecretDerivationMode, SecretKey};
pub mod kdf;

/// Alias for config entries in manifests
pub type ConfigEntry = String;

/// Magic header for latch encrypted files
const MAGIC: [u8; 4] = *b"LTCH";
