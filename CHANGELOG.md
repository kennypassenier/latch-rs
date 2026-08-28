# Changelog

## 2.1.0 — 2026-08-28

### Added (D9 — via mini-round on the frozen feature list)
- `latch project remove <name>`: retire a project — every environment's
  ciphertexts removed from the secrets repo as a normal commit+push
  (history stays; the command prints the rotate-the-values tip), local
  link and per-machine marker cleaned up. Keys are KEPT by default so
  the git history stays readable; `--purge-keys` deletes them too after
  a warning to take a key backup first. Interactive confirmation types
  the exact project name; headless requires `--yes`.
- `latch project list` is now repo-wide: every project in the secrets
  repo with per-environment ciphertext counts, marking which are linked
  on this machine — unlinked entries are the removal candidates the old
  link-only listing could not show.

## 2.0.1 — 2026-08-28

Bug-fix release. 2.0.0's discovery honoured `.gitignore`, so in any real
project it skipped exactly the files latch exists to manage.

### Fixed
- **Discovery no longer reads `.gitignore` (D1 amendment, D8).** Every
  project lists `.env` there; latch consequently found nothing and
  reported "0 file(s)" as a successful commit. Found while consuming
  latch from another project: a correct `.env` was never stored, silently.
  A parent repository's `.gitignore` could hide a subproject's `.env` too.
- **`.env.sample` is a template again**, like `.env.example` (v1 parity);
  2.0.0 would have encrypted it as a secret.
- **The secrets clone is listed unfiltered**: an ignore file that wandered
  into latch's own storage could have hidden a ciphertext from a pull.

### Added
- **`.latchignore`** (D8): latch's own exclusion file, gitignore format
  including negations, read only by latch. A built-in list is always
  skipped — `.git`, `.latch`, `node_modules`, `target`, `vendor`,
  `.venv`, `venv` — and a negation in the project-root `.latchignore`
  (`!vendor/`) lifts an entry. `latch init` leaves a commented starter
  file behind.
- **`latch status --no-ignore`**: lists the env files the rules are
  hiding. A view only; a commit still respects the rules.
- **A warning when discovery finds nothing**, naming the directory, the
  rules in play and that flag — instead of a success line reading
  "0 file(s)".

### Tests
- `crates/core/tests/d8_ignore_tests.rs`: 9 tests against the real
  filesystem and real git. The mock file backend has no ignore semantics,
  which is exactly why ~90 green tests never saw this.

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
