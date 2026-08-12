# Clone Groups (Pragma Pattern)

**Status:** Implemented  
**Category:** Workflow / DX  
**Commands affected:** `latch push` (aliases: `save`, `lock`), `latch pull` (aliases: `load`, `unlock`), `latch group`

## Summary

Multiple `.env` files can subscribe to one shared encrypted blob by adding a first-line pragma:

```dotenv
# latch:group=promtail_config
```

## Implemented Behavior

- Discovery parses `# latch:group=<name>` from the first line.
- Group names are validated to `[a-zA-Z0-9_-]+`.
- Subscribe-intent members (pragma only, no key/value pairs) resolve from the local `.latch/<env>/group.<name>.enc` cache populated by `latch pull`. A network call is not needed during `latch commit`.
- Divergence between members is detected and resolved interactively by selecting a source of truth.
- Group content is encrypted once per group and stored as `group.<name>.enc`.
- Pull fans out one decrypted group blob to all members.
- Manifest stores clone groups as units (`name`, `env`, `members`, `remote_blob`).
- `latch group list` and `latch group show` expose membership.
- `latch status` reports clone groups as sync units.

## Implementation Notes

- Save/push pipeline: `src/commands/push.rs`
- Pull/load pipeline: `src/commands/pull.rs`
- Group command: `src/commands/group.rs`
- Status integration: `src/commands/status.rs`
- Manifest model: `src/manifest/mod.rs`
- Pragma parsing and subscribe checks: `src/discovery/mod.rs`
