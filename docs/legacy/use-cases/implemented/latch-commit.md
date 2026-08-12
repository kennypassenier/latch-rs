# Use Case: `latch commit` — Local Encryption Staging Step

## Status: Implemented

## Summary

Introduce a new `latch commit` command (alias: `lock`) that encrypts `.env` files and stages
the encrypted blobs **locally** in a `.latch/` directory, without requiring a network connection.
`latch push` is updated to **only** upload the pre-staged blobs to GitHub; encryption moves
entirely into `commit`. `latch pull` (alias: `unlock`) is updated to also cache the downloaded
encrypted blobs to `.latch/` so that subsequent `commit` runs can resolve subscribe-intent
clone-group members from the local cache.

The three-step flow mirrors a familiar git mental model:

```
latch commit   →  encrypt + stage locally in .latch/
latch push     →  upload .latch/ blobs to GitHub
latch pull     →  download from GitHub + cache to .latch/ + decrypt to filesystem
```

---

## Motivation

The current two-step flow (`push` / `pull`) conflates encryption and network I/O into a single
command.  Separating them provides several benefits:

- **Offline-first commit**: Secrets can be encrypted without network access.  Push happens when
  connectivity is available.
- **Cleaner alias semantics**: `lock` = seal your secrets locally; `unlock` = open them from
  the remote.  Previously `lock` was an alias for the upload command, which was confusing.
- **Better clone-group behaviour**: Subscribe-intent members (files that only carry the pragma
  and no key=value pairs) previously required a GitHub round-trip during `commit`.  After this
  change they resolve against the local `.latch/` cache, which is populated by `latch pull`.
- **Separable concerns in CI**: A CI pipeline can `commit` in a sandboxed step, then `push` in
  a step that has network access, without mixing encryption keys with GitHub tokens in the same
  environment.

---

## Detailed Behaviour

### `latch commit [--env <name>]`  (alias: `lock`)

1. Locate the project root via `ProjectConfig::find_and_load`.
2. Resolve credentials (key only; no PAT required).
3. Scan all `.env` files under the project root (same discovery logic as before).
4. For each file belonging to a clone group (pragma present):
   - Detect subscribe-intent (pragma only, no `KEY=VALUE` pairs).
   - Subscribe-intent: read the canonical content from `.latch/<env>/group.<name>.enc` if it
     exists; otherwise print a warning and skip ("Run `latch pull` first").
   - Divergence resolution (multiple content-bearing members with differing content) is
     interactive — same `Select` prompt as before.
   - Write canonical content back to all member files + generate `.env.example` files.
   - Encrypt canonical bytes → write to `.latch/<env>/group.<name>.enc`.
5. For each standalone file:
   - Read plaintext, generate `.env.example`.
   - Encrypt → write to `.latch/<env>/<flat>.enc` (path-flattened name, e.g. `backend__.env.enc`).
6. Write a local staging manifest to `.latch/staging.json` (same `Manifest` JSON format as the
   remote `{project}/manifest.json`, but stored locally).
7. No GitHub calls; no PAT required.

### `latch push [--env <name>]`

1. Load `.latch/staging.json`.  If absent or the requested env has no staged files → error with
   guidance to run `latch commit` first.
2. Obtain PAT from credentials.
3. Fetch the **remote** manifest from GitHub (for cleanup of files removed since last push).
4. For each staged standalone file: read `.latch/<env>/<flat>.enc`, upload to GitHub.
5. For each staged group: read `.latch/<env>/group.<name>.enc`, upload to GitHub.
6. Delete remote files/groups that were in the old remote manifest but are no longer staged.
7. Update the remote manifest on GitHub.
8. No encryption; no key required.

### `latch pull [--env <name>]`  (alias: `unlock`)

1. Existing behaviour (download manifest → download blobs → overwrite-protect → decrypt to
   filesystem) is preserved.
2. **New**: After each blob download, cache the raw ciphertext to `.latch/<env>/<flat>.enc` (or
   `.latch/<env>/group.<name>.enc`).
3. **New**: After all blobs are written, persist the remote manifest as `.latch/staging.json`.
   This ensures subscribe-intent group members can be committed offline after a pull.

---

## `.latch/` Directory Layout

```
<project-root>/
  .latch/
    staging.json          ← local manifest (same schema as remote manifest.json)
    dev/
      .env.enc            ← encrypted standalone file
      backend__.env.enc   ← path-flattened encrypted file
      group.shared.enc    ← encrypted clone-group blob
    prod/
      .env.enc
```

The `.latch/` directory contains **only encrypted data**.  It is safe to commit to the
project's own git repository.  Latch does **not** add `.latch/` to `.gitignore`.

---

## Alias Changes

| Old alias | Old command | New alias | New command  |
|-----------|-------------|-----------|--------------|
| `save`    | `push`      | `save`    | `push` (kept for compat) |
| `lock`    | `push`      | `lock`    | `commit`     |
| `load`    | `pull`      | `load`    | `pull` (kept for compat) |
| `unlock`  | `pull`      | `unlock`  | `pull` (unchanged) |

---

## Files Affected

- `src/commands/commit.rs` (new)
- `src/commands/push.rs` (rewrite: upload-only, no encryption)
- `src/commands/pull.rs` (update: cache blobs to `.latch/`)
- `src/commands/mod.rs` (add `pub mod commit`)
- `src/main.rs` (add `Commit` subcommand; move `lock` alias from `Push` to `Commit`)
- `src/manifest/mod.rs` (add `load_staging`, `save_staging`, `local_staging_path` helpers)
- `src/discovery/mod.rs` (add `local_blob_path`, `local_group_blob_path` helpers)
- `docs/use-cases/implemented/latch-push.md` (update)
- `docs/use-cases/implemented/latch-pull.md` (update)
- `docs/use-cases/implemented/clone-groups.md` (update: subscribe-intent resolves from cache)

---

## Implementation Notes

- The `Manifest` struct is reused as-is for `staging.json`; no new types needed.
- `push` does not need the encryption key — only the PAT.
- `commit` does not need the PAT — only the encryption key.
- After `latch pull`, running `latch commit` offline then `latch push` later is fully supported.
- `latch rotate` continues to work against GitHub directly (it re-encrypts on the fly); after a
  rotate the local `.latch/` cache will be stale until the next `pull`.
