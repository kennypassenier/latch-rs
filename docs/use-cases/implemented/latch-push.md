# latch push

**Status:** Implemented  
**Category:** Workflow  
**Aliases:** `save`

## Summary

Upload the staged encrypted blobs from the local `.latch/` directory to the secrets repository.
Requires `latch commit` to have been run first. No encryption key is needed — only a GitHub PAT.
Updates the remote manifest and removes stale remote files.

## User Story

As a developer who has run `latch commit` to encrypt their secrets locally, I want to run
`latch push` to upload the staged ciphertexts to the shared remote so my teammates can pull
the latest version.

## Acceptance Criteria

- Reads staged file list from `.latch/staging.json`.
- Errors clearly if nothing is staged (guides user to run `latch commit` first).
- Reads each encrypted blob from `.latch/<env>/<flat>.enc` and uploads to `{project}/{env}/{flat}.enc`.
- Removes remote files that were previously tracked but are no longer staged.
- Updates `manifest.json` in the secrets repo.
- Shows a progress bar during upload.
- Accepts `--env` / `-e` flag (default: `dev`).
- Does **not** require the encryption key — only the GitHub PAT.

## Command

```bash
latch push [--env <env>]
```

## Typical Flow

```bash
latch commit --env dev   # encrypt + stage locally (no network)
latch push   --env dev   # upload staged blobs to GitHub
```

## Implementation Notes

- `src/commands/push.rs`.
- See also: `docs/use-cases/implemented/latch-commit.md`.
