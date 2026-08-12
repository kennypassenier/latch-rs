# CLI Scaffolding

**Status:** Implemented  
**Category:** Core Infrastructure

## Summary

Set up the `clap`-based CLI entry point with all top-level subcommands and global flags.

## User Story

As a developer, I want a clean CLI interface so I can run `latch --help` and immediately understand every available command and how to use it.

## Acceptance Criteria

- `latch --help` lists all subcommands with descriptions.
- `latch <subcommand> --help` shows per-command flags and examples.
- Global `--verbose` / `-v` flag (stackable: `-v` = info, `-vv` = debug) works across all subcommands.
- Global `--env` / `-e` flag sets the environment label for commands that use it.
- Argument parsing maps correctly to typed structs.

## Commands Covered

`latch login`, `latch init`, `latch push`, `latch pull`, `latch status`, `latch run`, `latch rotate`, `latch key`, `latch path`, `latch project`, `latch clone`, `latch commit`

## Implementation Notes

- Uses `clap` with derive macros.
- `Commands` enum is defined in `src/main.rs`.
- Global `verbose` is a `u8` count action (each `-v` increments).
- Build version falls back to `CARGO_PKG_VERSION` but accepts `LATCH_BUILD_VERSION` env override.
