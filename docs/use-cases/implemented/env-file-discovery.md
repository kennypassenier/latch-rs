# .env File Discovery

**Status:** Implemented  
**Category:** Auto-Discovery

## Summary

Recursively scan the project tree for `.env` files and variants, respecting `.latchignore` rules. `.gitignore` is intentionally bypassed so secrets-related files remain discoverable.

## User Story

As a developer with a monorepo, I want Latch to automatically find every `.env` file in my project without me listing them manually, while still being able to exclude specific paths with a `.latchignore`.

## Acceptance Criteria

- Finds `.env`, `.env.local`, `.env.production`, etc.
- Skips `.env.example` and `.env.sample` (templates, not secrets).
- Respects `.latchignore` (gitignore-format custom ignore file).
- Does NOT respect `.gitignore` (secrets may be gitignored intentionally).
- Never descends into `.latch/` or `target/` directories.
- Hidden files (dotfiles) are included, not skipped.

## Implementation Notes

- `scan_env_files()` in `src/discovery/mod.rs`.
- Uses `ignore::WalkBuilder` with `git_ignore(false)` and `hidden(false)`.
- Custom ignore filename: `.latchignore`.
