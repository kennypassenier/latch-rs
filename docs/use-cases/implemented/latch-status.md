# latch status

**Status:** Implemented  
**Category:** Workflow

## Summary

Compare local `.env` files against their remote encrypted counterparts and display a concise per-file sync report.

## User Story

As a developer, I want to quickly see whether my local secrets are in sync with the remote without having to manually decrypt and diff files.

## Acceptance Criteria

- Fetches and decrypts each tracked file for the given env.
- Compares plaintext with local file.
- Outputs one line per file with a clear status icon:
  - `✓ in sync`
  - `~ modified`
  - `! missing` (remote has it, local doesn't)
  - `✗ error` (with error detail)
- Exits with non-zero code if any file is out of sync.
- Accepts `--env` / `-e` flag (default: `dev`).

## Command

```bash
latch status [--env <env>]
```

## Implementation Notes

- `src/commands/status.rs`.
