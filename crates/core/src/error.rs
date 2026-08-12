//! The failure model (AR6): every error an operator can hit carries a
//! remedy line — "what now?" is part of the error, not an exercise for the
//! reader. Programmatic callers match on the variant; humans read
//! `Display` which always ends with the remedy.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LatchError {
    /// Ciphertext or header failed authentication (K1/AR10): tampering,
    /// corruption, or truncation — never partially decrypted.
    #[error("integrity check failed for {context} :: the file is corrupt or was tampered with — restore it from git history (latch history) or re-push from a machine with a good copy")]
    Integrity { context: String },

    /// The envelope says it was sealed with a key we don't have (AR10 makes
    /// this distinguishable from corruption).
    #[error("{context} is encrypted with key '{needed}' (generation {generation}) which is not available here :: pull that key onto this machine (latch clone / latch key restore) or rotate and re-push")]
    WrongKey {
        context: String,
        needed: String,
        generation: u16,
    },

    /// Not a latch v2 envelope at all, or a future format version.
    #[error("{context}: {detail} :: if this file comes from latch v1, v2 does not read it (clean break, AR4) — re-push it with v2; if it comes from a newer latch, update this binary (latch update)")]
    Format { context: String, detail: String },

    /// Passphrase-based key derivation failed (bad parameters, not a wrong
    /// passphrase — that surfaces as Integrity when decryption fails).
    #[error("key derivation failed: {detail} :: this is a bug in latch, not your input — please report it")]
    KeyDerivation { detail: String },

    /// Anything else, with the remedy supplied at the call site.
    #[error("{what} :: {remedy}")]
    Other { what: String, remedy: String },
}

impl LatchError {
    pub fn other(what: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self::Other {
            what: what.into(),
            remedy: remedy.into(),
        }
    }
}
