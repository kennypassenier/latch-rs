# Encryption Engine

**Status:** Implemented  
**Category:** Cryptography

## Summary

XChaCha20-Poly1305 AEAD encryption/decryption with Argon2id-based key derivation and secure random nonce generation.

## User Story

As a security-conscious team, I want all `.env` files encrypted with a strong authenticated cipher so that even if the secrets repository is leaked, the contents are unreadable without the key.

## Acceptance Criteria

- Encryption uses XChaCha20-Poly1305.
- 24-byte nonce is randomly generated per encryption and prepended to the ciphertext.
- Key derivation: Argon2id when user provides a passphrase; raw 32-byte key when user provides hex/base64.
- Decryption verifies Poly1305 MAC; tampered ciphertext fails with a clear error.
- Roundtrip: `decrypt(encrypt(plaintext, key), key) == plaintext`.

## Key Formats Accepted

- 64-char hex string (32 bytes).
- 44-char base64 string (32 bytes).
- Passphrase (Argon2id-derived, requires salt stored in manifest).

## Implementation Notes

- `src/crypto/mod.rs` — encrypt/decrypt wrappers.
- `src/crypto/kdf.rs` — Argon2id key derivation.
- Salt stored as base64 in `manifest.json` (`kdf_salt` field).
