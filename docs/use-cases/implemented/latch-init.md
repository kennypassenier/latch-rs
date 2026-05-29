# latch init

**Status:** Implemented  
**Category:** Workflow

## Summary

Interactive one-time project initialisation. Creates `.latch/config.toml`, links the folder to a project in the secrets repo, and pushes an initial manifest if one doesn't exist.

## User Story

As a developer setting up a new project, I want to run a single command that walks me through configuring Latch so I can start saving secrets immediately.

## Acceptance Criteria

- Prompts for: project name, default environment, encryption key (generate / passphrase / paste).
- Reuses PAT and secrets repo from `latch login` defaults.
- Writes `.latch/config.toml` with `name`, `secrets_repo`, `default_env`.
- Pushes an empty manifest to the secrets repo if none exists.
- Key is stored in the OS keyring, never in the config file.

## What Gets Created

```
.latch/
  config.toml    ← commit this
.latchignore     ← commit this (optional, created if absent)
```

## Implementation Notes

- `src/commands/init.rs`.
- Uses `dialoguer` for interactive prompts.
