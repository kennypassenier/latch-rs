//! latch v2 core (AR1): all domain logic lives here, with zero ambient
//! I/O. Anything that touches processes, files, network, clocks or
//! randomness-with-consequences goes through injected traits so every
//! test runs against mocks. The CLI and TUI are thin shells.

pub mod config;
pub mod credentials;
pub mod discovery;
pub mod envelope;
pub mod error;
pub mod groups;
pub mod kdf;
pub mod keys;
pub mod lock;
pub mod ops;
pub mod platform;
pub mod repo;
pub mod template;
