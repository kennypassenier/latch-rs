# Credential Management

**Status:** Implemented  
**Category:** Security

## Summary

Unified credential resolution across OS keyring and environment variables, with a fallback chain that supports both interactive and headless (CI/CD) use.

## User Story

As a CI/CD pipeline, I want to provide `LATCH_PAT` and `LATCH_KEY` as environment variables so that Latch can encrypt and decrypt secrets without a human-interactive keyring.

As a developer on a workstation, I want my PAT and key stored securely in my OS keyring so I never have to paste them into a terminal after the first setup.

## Acceptance Criteria

- `CredentialProvider` trait defines `get_pat()`, `get_key()`, `set_credentials()`.
- `KeyringProvider` uses the OS keyring (`keyring` crate), namespaced by project name to prevent collisions.
- `EnvVarProvider` reads `LATCH_PAT` and `LATCH_KEY`.
- `FallbackChain` tries keys in deterministic order: `LATCH_KEY` → global keyring (`global.key`) → global config fallback (`global_key_hex`) → env/project keyring slots → project config fallback.
- All providers are mockable for testing.

## Credential Fallback Order

1. Environment variable — `LATCH_KEY` (explicit override)
2. OS keyring — `global.key` (global encryption key)
3. `~/.latch/config.toml` — `global_key_hex` (global fallback)
4. OS keyring — `<project>.key.<env>` (env-specific)
5. OS keyring — `<project>.key` (project-wide)
6. `~/.latch/config.toml` — `key_hex` (project fallback)
7. OS keyring — `github.pat` and `github.secrets_repo` (global)
8. OS keyring — `<project>.pat` (legacy)
9. PAT fallbacks — `LATCH_PAT`, `global_pat`, `github_pat`

## Implementation Notes

- `src/credentials/mod.rs` — `FallbackChain`
- `src/credentials/keyring_provider.rs` — OS keyring
- `src/credentials/env_provider.rs` — environment variables
