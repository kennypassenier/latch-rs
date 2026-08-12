# latch run

**Status:** Implemented  
**Category:** Workflow / Security

## Summary

Run a subprocess with decrypted secrets injected directly into its environment. Secrets never touch the filesystem.

## User Story

As a developer or CI pipeline, I want to start a process with secrets available as environment variables without writing plaintext to disk, minimising the attack surface.

## Acceptance Criteria

- Fetches and decrypts all tracked files for the given env.
- Parses key=value pairs (skipping comments and blank lines).
- Expands template references (`${VAR}`, `$VAR`) across the full set of variables.
- Injects all resolved pairs into the subprocess environment.
- Propagates the subprocess exit code.
- Plaintext is never written to any file.
- Accepts `--env` / `-e` flag (default: `dev`).

## Command

```bash
latch run [--env <env>] -- <program> [args…]
```

## Examples

```bash
latch run -- node server.js
latch run --env prod -- python manage.py collectstatic
latch run --env staging -- npm run migrate
```

## Implementation Notes

- `src/commands/run.rs`.
- Template expansion via `expand_env_vars()` in `src/discovery/mod.rs`.
