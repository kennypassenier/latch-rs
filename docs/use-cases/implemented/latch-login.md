# latch login

**Status:** Implemented  
**Category:** Setup

## Summary

Interactively store global GitHub credentials (PAT and default secrets repo) in the OS keyring. Run once per machine.

## User Story

As a developer on a new machine, I want to run `latch login` once to store my GitHub PAT so that all subsequent Latch commands work without re-entering credentials.

## Acceptance Criteria

- Prompts for GitHub PAT.
- Prompts for default secrets repo (`owner/repo` format).
- Stores both values in the OS keyring under global slots (`github.pat`, `github.secrets_repo`).
- Does not write secrets to any config file.
- Subsequent commands pick up PAT from keyring automatically.

## Command

```bash
latch login
```

## Implementation Notes

- `src/commands/login.rs`.
