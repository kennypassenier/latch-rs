# .env.example Generation

**Status:** Implemented  
**Category:** Auto-Discovery / DX

## Summary

Automatically generate a `.env.example` file next to each discovered `.env` during `latch push`. Values are stripped; keys, comments, and blank lines are preserved.

## User Story

As a developer committing a new project, I want Latch to generate a safe `.env.example` automatically so teammates know which variables exist without exposing their values.

## Acceptance Criteria

- `KEY=secret_value` → `KEY=` (value stripped).
- Comment lines (`# ...`) are preserved unchanged.
- Blank lines are preserved unchanged.
- Lines without `=` are preserved as-is.
- `.env.example` is written next to the source `.env`.
- `.env.example` is safe to commit — it contains no secret values.

## Implementation Notes

- `generate_example()` and `write_example()` in `src/discovery/mod.rs`.
- Called automatically during `latch push`.
