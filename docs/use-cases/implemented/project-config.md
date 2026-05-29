# Project Configuration

**Status:** Implemented  
**Category:** Core Infrastructure

## Summary

Walk upward from the current directory to find `.latch/config.toml` and load project metadata (name, secrets repo, default env).

## User Story

As a developer, I want to run `latch push` from any subdirectory of my project and have Latch automatically find the project root without me specifying a path.

## Acceptance Criteria

- Walking upward from any child directory finds the nearest `.latch/config.toml`.
- `~/.latch/config.toml` (global) is explicitly skipped so only project-local config is loaded.
- Clear error message if no project config is found: `"No .latch/config.toml found. Run 'latch init' in your project root."`.
- `ProjectConfig` exposes `name`, `secrets_repo`, `default_env`.

## Implementation Notes

- `ProjectConfig::find_and_load()` in `src/config/project.rs`.
- Returns `(ProjectConfig, PathBuf)` where the `PathBuf` is the project root.
- TOML parsed with `toml` crate.
