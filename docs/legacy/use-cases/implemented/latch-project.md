# latch project

**Status:** Implemented  
**Category:** Setup / Workflow

## Summary

Interactively bind the current directory to an existing remote project without going through the full `latch init` flow. Useful when joining a project someone else already initialised.

## User Story

As a new team member, I want to run `latch project` to select the right project from the secrets repo and configure my local folder without initialising from scratch.

## Acceptance Criteria

- Reads PAT and secrets repo from the keyring (or accepts `--repo` override).
- Lists available projects from the secrets repo.
- Lets the user select a project interactively.
- Lets the user select or input an environment.
- Writes `.latch/config.toml` locally.
- Optionally runs `latch pull` immediately after binding.
- `--list` flag lists projects and exits without writing anything.

## Command

```bash
latch project [--repo <owner/repo>] [--env <env>] [--list]
```

## Implementation Notes

- `src/commands/project.rs`.
