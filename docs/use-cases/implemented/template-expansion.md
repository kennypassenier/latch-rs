# Template Variable Expansion

**Status:** Implemented  
**Category:** DX / Workflow

## Summary

Expand `${VAR}` and `$VAR` references within `.env` values, using variables defined earlier in the same file or already present in the process environment.

## User Story

As a developer, I want to write `DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/mydb` in my `.env` so I don't repeat the same values multiple times.

## Acceptance Criteria

- `${VAR}` and `$VAR` syntax both expand.
- Expansion lookup order:
  1. Variables resolved earlier in the same file (left-to-right line order).
  2. Current process environment.
- Unknown variables expand to empty string (no error).
- Expansion happens before injection into subprocess (for `latch run`) and before comparison in `latch status`.

## Example

```dotenv
DB_HOST=localhost
DB_PORT=5432
DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/mydb
```

→ `DATABASE_URL` expands to `postgres://localhost:5432/mydb`.

## Implementation Notes

- `expand_env_vars()` in `src/discovery/mod.rs`.
- Used in `src/commands/run.rs`.
