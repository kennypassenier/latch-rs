# Global Configuration

**Status:** Implemented  
**Category:** Core Infrastructure

## Summary

Load and persist global user-level configuration at `~/.latch/config.toml`, covering the GitHub PAT, default secrets repo, and known project list.

## User Story

As a developer, I want to run `latch login` once on a machine and never be asked for my GitHub PAT again across any project.

## Acceptance Criteria

- `~/.latch/` directory is created automatically if absent.
- `~/.latch/config.toml` is read on startup; missing file is treated as empty config, not an error.
- `GlobalConfig` serialises/deserialises cleanly via `toml`.
- Known projects list is updated when `latch init` adds a new project.

## Implementation Notes

- `GlobalConfig` struct in `src/config/global.rs`.
- Path resolved via `dirs::home_dir()`.
- Stored as TOML for human readability.
