# Changelog

## 2.0.0 — 2026-08-12

A ground-up Rust rewrite ("v2"). A clean break from v1: new on-disk
format, no automatic migration, v1 kept beside it as the `latch-legacy`
package.

### Platforms
- Linux (fully verified) and Windows 11 (built + CI-checked; runtime
  verification pending on real hardware — treat Windows as beta until the
  `docs/WINDOWS_TEST_CHECKLIST.md` pass is done). MSRV 1.86.

### Architecture
- Workspace split: `latch-core` (all logic, zero ambient I/O behind
  platform traits — everything mockable), `latch` CLI, `latch-ui` TUI.
- Storage is a real local **git clone** driven through the `git` binary
  (replaces v1's bespoke GitHub-API blob storage and its corruption bugs);
  history, rollback and offline use are plain git.
- Authenticated XChaCha20-Poly1305 envelope with a pinned byte format and
  Argon2id KDF (regression-vector locked — the format can't drift).

### Reliability fixes over v1
- Credential chain **env → encrypted file → OS keyring** (fixes
  keyring-only failing on LXC containers).
- **Never hangs**: without a TTY every would-be prompt is a hard error
  naming its answer (M7) — the v1 sync-stall class is designed out.
- Every error carries a remedy in the message itself.

### Features
- Per-environment keys, key rotation, key backup/restore, machine clone
  (X25519, one scoped command over ssh), file groups (pragma-linked shared
  content across projects), template expansion, masked diff, zero-disk
  edit, repo-wide verify, offline cache, shell completions, project
  management.
- A management TUI: dashboard, key matrix, masked secrets editor,
  history/rollback, doctor, clone wizard.

### Security & self-update
- Signed, cross-platform self-update: the checksum manifest must carry a
  valid **minisign signature** under a baked-in key before any byte is
  trusted; keeps the previous binary; refuses downgrades; fails closed.
  Signing is local (never in CI).
- Hardening pass closing an external review: path-traversal write fix,
  repo-URL validation, crash-safe key rotation, ownership-checked mutation
  lock, cross-machine group-divergence detection, passphrase zeroize,
  core-dump disable, and more — each landed test-first.

### Engineering
- 88 automated tests (most end-to-end against real git); CI enforces
  format, lint (warnings-as-errors), the full suite, MSRV, and a Windows
  build; `main` is branch-protected.
