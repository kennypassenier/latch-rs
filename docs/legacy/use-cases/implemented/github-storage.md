# GitHub Remote Storage

**Status:** Implemented  
**Category:** Remote Storage

## Summary

Push and pull encrypted files to/from a private GitHub repository using the GitHub Contents API, with SHA-based conflict detection to prevent accidental overwrites.

## User Story

As a developer, I want my encrypted secrets stored in a private GitHub repository I already control so that I don't need to manage a separate secrets server.

## Acceptance Criteria

- `push_file()` uploads a file; if the file already exists, fetches its current SHA and includes it in the update request.
- `pull_file()` downloads raw bytes from a path in the repo.
- `delete_file()` removes a file given its SHA.
- `get_sha()` retrieves the current blob SHA for a path, or returns `None` if absent.
- `RemoteStorage` trait allows mock implementations for testing.
- No HTTP calls in unit tests — mocked via `MockRemoteStorage`.

## Remote Path Structure

```
{project}/
  manifest.json
  {env}/
    {flat-name}.enc
```

## Implementation Notes

- `src/github/client.rs` — `GitHubClient`.
- `src/github/mod.rs` — `RemoteStorage` trait.
- Uses `reqwest` for HTTP.
- Content is base64-encoded per GitHub API spec.
