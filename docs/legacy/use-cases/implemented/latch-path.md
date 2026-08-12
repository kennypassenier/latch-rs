# latch path

**Status:** Implemented  
**Category:** Installation / DX

## Summary

Install or remove the current Latch binary from a user-level PATH location, and report installation status.

## User Story

As a developer, I want to run `latch path add` once after downloading the binary so that `latch` is available globally from any terminal without using `./latch`.

## Acceptance Criteria

- `latch path add` copies the binary to a user-level directory and adds it to the shell PATH.
- `latch path remove` undoes the PATH block and removes the managed binary.
- `latch path status` shows current binary path, install location, and whether PATH is configured.
- Works on Linux/macOS (`~/.local/bin/`) and Windows (`%LOCALAPPDATA%\Programs\latch\`).
- Shell profile files are updated with a clearly-marked block that `remove` can cleanly undo.

## Command

```bash
latch path add
latch path remove
latch path status
```

## Implementation Notes

- `src/commands/path.rs`.
