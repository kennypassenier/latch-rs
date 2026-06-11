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
- `FallbackChain` tries: env-specific keyring slot → project keyring slot → global keyring slot (`global.key`) → env vars → global/project config fallback.
- All providers are mockable for testing.

## Credential Fallback Order

1. OS keyring — `<project>.key.<env>` (env-specific)
2. OS keyring — `<project>.key` (project-wide)
3. OS keyring — `global.key` (global encryption key)
4. OS keyring — `github.pat` and `github.secrets_repo` (global)
5. OS keyring — `<project>.pat` (legacy)
6. Environment variables — `LATCH_KEY` / `LATCH_PAT`
7. `~/.latch/config.toml` — `global_key_hex` / `global_pat` / `default_secrets_repo` / `key_hex` / `github_pat`

## Implementation Notes

- `src/credentials/mod.rs` — `FallbackChain`
- `src/credentials/keyring_provider.rs` — OS keyring
- `src/credentials/env_provider.rs` — environment variables
