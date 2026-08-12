# Path Flattening

**Status:** Implemented  
**Category:** Auto-Discovery

## Summary

Convert relative local paths to a flat remote filename by replacing path separators with `__` while preserving file names exactly (including leading dots).

## User Story

As a system, I need to store files with nested paths (e.g., `backend/api/.env`) as flat filenames in a GitHub repository without collisions and without relying on manifest-only reconstruction.

## Acceptance Criteria

- `.env` → `.env`
- `backend/.env` → `backend__.env`
- `src/api/.env` → `src__api__.env`
- `frontend/.env.local` → `frontend__.env.local`
- Works correctly on both Unix (`/`) and Windows (`\\`) separators.

## Remote Path Format

`{project}/{env}/{flat}.enc`

Example: `my-app/prod/src__api__.env.enc`

## Implementation Notes

- `flatten_path()` and `remote_path()` in `src/discovery/mod.rs`.
- Separator strategy changed from dot-join to `__` to avoid ambiguous flattening.
