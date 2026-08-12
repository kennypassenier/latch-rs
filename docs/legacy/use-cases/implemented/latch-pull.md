# latch pull

**Status:** Implemented  
**Category:** Workflow  
**Aliases:** `load`, `unlock`, `export`

## Summary

Download encrypted files from the secrets repository, cache them to `.latch/<env>/`, update
the local staging manifest, and decrypt them to their original local paths.

## User Story

As a developer joining a project or pulling the latest secrets, I want to run `latch pull` to
get the current remote state written to my local `.env` files automatically. After pulling, I
can run `latch commit` offline and then `latch push` once connectivity is restored.

## Acceptance Criteria

- Fetches `manifest.json` to know which files to pull.
- Downloads and decrypts each tracked file for the given env.
- Caches each downloaded encrypted blob to `.latch/<env>/` for offline `commit` support.
- Saves the remote manifest as `.latch/staging.json` so subscribe-intent clone-group members
  can resolve from the local cache without a network call.
- Writes files to their correct local paths (creates parent directories if needed).
- If a local file already exists and differs from remote, prompts for confirmation before overwriting.
- `--dry-run` flag shows what would be written without touching the filesystem.
- Shows a progress bar during download.
- Reports how many files were written vs skipped.

## Command

```bash
latch pull [--env <env>] [--dry-run]
```

## Implementation Notes

- `src/commands/pull.rs` (command handler, aliased as `load` / `unlock`).
- See also: `docs/use-cases/implemented/latch-commit.md`.
