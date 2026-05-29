# Secret Versioning

**Status:** Implemented  
**Category:** Safety / Recovery  
**Commands affected:** `latch history`, `latch rollback`, `latch push`/`latch pull`

## Summary

Latch uses GitHub commit history in the secrets repository as the version store. `latch history` shows recent project commits, and `latch rollback` restores a previous state by creating a new forward commit.

## Implemented Behavior

- `latch history [--env <env>] [--limit <n>]` lists recent commits touching the manifest.
- `latch rollback --steps <n>` restores to a previous commit by replaying old encrypted blobs into HEAD.
- `latch rollback --to <sha>` restores to a specific commit SHA.
- Rollback is append-only (forward commit), never history rewrite.
- Rollback restores standalone files, clone group blobs, and manifest env/group state for the selected environment.

## Commit Message Convention

Structured commit titles are emitted for save/group/rollback flows to keep history readable.

## Implementation Notes

- History command: `src/commands/history.rs`
- Rollback command: `src/commands/rollback.rs`
- GitHub history/ref APIs: `src/github/mod.rs`, `src/github/client.rs`
