# latch login

**Status:** Implemented  
**Category:** Setup

## Summary

Store global credentials (PAT, KEY, default secrets repo) once per machine, with keyring-first storage and a durable file fallback.

## User Story

As a developer on a new machine or LXC container, I want to run `latch login` once to store PAT and KEY so all Latch commands can always authenticate and decrypt without re-entering credentials.

## Acceptance Criteria

- Accepts non-interactive flags: `--PAT` / `--KEY` / `--REPO` (and legacy `-PAT` / `-KEY` / `-REPO`).
- Prompts for missing values when flags are omitted.
- Defaults secrets repo to `kennypassenier/secrets` when not provided.
- Stores PAT/KEY/repo in OS keyring under global slots (`github.pat`, `global.key`, `github.secrets_repo`) when available.
- Always persists fallback values to `~/.latch/config.toml` (`global_pat`, `global_key_hex`, `default_secrets_repo`).
- Subsequent commands resolve PAT/KEY from keyring or fallback config automatically.

## Command

```bash
latch login

# non-interactive
latch login -PAT ghp_xxx -KEY 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Implementation Notes

- `src/commands/login.rs`.
