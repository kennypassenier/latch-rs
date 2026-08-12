# Multi-Key Environments

**Status:** Implemented  
**Category:** Security

## Summary

Support separate encryption keys per environment (e.g., `dev`, `staging`, `prod`) so that access to dev secrets does not imply access to production secrets.

## User Story

As a security-conscious team, I want the dev key and prod key to be completely separate so that a developer with only dev access cannot decrypt production secrets, even from the same project.

## Acceptance Criteria

- `latch key --env prod` stores a key under `<project>.key.prod` in the keyring.
- Commands that accept `--env` resolve the env-specific key first, falling back to the project-wide key.
- `latch push --env prod` encrypts with the prod key.
- `latch pull --env prod` decrypts with the prod key.
- Attempting to decrypt a prod payload with a dev key fails with a clear MAC error.
- `latch key` (no `--env`) updates the default project-wide key.

## Command

```bash
latch key [--env <env>]
```

## Keyring Slot Convention

| Slot | Purpose |
|---|---|
| `<project>.key` | Project-wide default key |
| `<project>.key.<env>` | Environment-specific key |

## Implementation Notes

- `src/commands/key.rs`.
- `FallbackChain::get_key_for_env()` in `src/credentials/mod.rs`.
