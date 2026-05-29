# Manifest

**Status:** Implemented  
**Category:** Remote Storage

## Summary

A `manifest.json` file stored in the secrets repository acts as a routing table mapping environments to their tracked file paths.

## User Story

As a developer running `latch pull`, I want Latch to know exactly which remote encrypted files belong to my project and where to restore them locally, without me providing a file list.

## Acceptance Criteria

- `manifest.json` is stored at `{project}/manifest.json` in the secrets repo.
- It records: schema version, project name, optional KDF salt, and a map of `env → [FileMapping]`.
- `FileMapping` stores the local relative path of a file.
- Manifest is updated on every `latch push`.
- Stale entries (files no longer present locally) are removed from the manifest on save.
- Manifest is fetched before any load or status operation.

## Schema (v1)

```json
{
  "version": 1,
  "project": "my-app",
  "kdf_salt": "base64...",
  "envs": {
    "dev": [
      { "local_path": "backend/.env" }
    ],
    "prod": [
      { "local_path": "backend/.env" },
      { "local_path": "worker/.env" }
    ]
  }
}
```

## Implementation Notes

- `src/manifest/mod.rs` — `Manifest` and `FileMapping` structs.
