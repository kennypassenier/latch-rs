# latch

Encrypted `.env` secrets, done right.

latch keeps secrets **out of your application repos**: every `.env` file
is sealed with XChaCha20-Poly1305 and stored as ciphertext in one private
GitHub repository. Plaintext exists in your working tree, in process
memory, or on tmpfs — never in git, never in argv, never in logs.

```
latch login --repo you/secrets     # once per machine
latch init                         # once per project
latch commit && latch push         # encrypt + upload
latch pull                         # anywhere else
latch run -- docker compose up     # secrets straight into the process
```

## Why latch

- **A real git repo as the backend** — history, rollback and offline use
  are `git log`, `git checkout` and the local clone; nothing bespoke to
  trust. Overwrite protection is git's own non-fast-forward refusal.
- **Authenticated envelopes** — every ciphertext names the key that opens
  it in a header that is itself authenticated; any tampering, anywhere,
  fails loudly. The byte format is frozen by regression vectors.
- **Credentials that work everywhere** — OS keyring on desktops, an
  Argon2id-encrypted file on servers/LXCs, environment variables for
  orchestration. Same commands in all three worlds.
- **File groups** — share one file's content across projects with a
  one-line pragma; one edit fans out at commit, two conflicting edits are
  a hard error with an explicit resolve.
- **Per-env keys, rotation, offline key backups** — blast-radius
  isolation and a real answer to "all my machines died".
- **Machine clone** — `latch clone --to user@host` moves exactly the
  credentials you scope, end-to-end encrypted with a verify code.
- **Never hangs** — without a TTY every would-be prompt is a hard error
  naming the flag or variable that answers it. Every error ends with a
  remedy.
- **A management TUI** — `latch ui`: dashboard, key matrix, masked
  secrets editor, history/rollback, doctor, clone wizard.

## Install

Linux and Windows 11 (AR17); MSRV 1.86. Download the release binary for
your OS, or build from source:

```
cargo build --release -p latch-cli    # target/release/latch
```

Later updates: `latch update` (checksum-verified, keeps the previous
binary, refuses anything that doesn't provably run).

## Documentation

| Doc | What's in it |
|---|---|
| [USER_GUIDE](docs/USER_GUIDE.md) | every command, per feature ID |
| [OPERATIONS_RUNBOOK](docs/OPERATIONS_RUNBOOK.md) | procedures: new machine, rotation, recovery, CI |
| [DEBUGGING_GUIDE](docs/DEBUGGING_GUIDE.md) | evidence trail + symptom→cause |
| [ARCHITECTURE_REFERENCE](docs/ARCHITECTURE_REFERENCE.md) | how and why it is built this way |
| [TEST_PLAN](docs/TEST_PLAN.md) | what is proven and where |
| [FEATURES](docs/FEATURES.md) / [ARCHITECTURE_DECISIONS](docs/ARCHITECTURE_DECISIONS.md) / [REALIZATION_PLAN](docs/REALIZATION_PLAN.md) | the v2 design record |

## Repository layout

```
crates/core   latch-core — all logic, zero ambient I/O (everything mockable)
crates/cli    the latch binary — a thin shell
crates/ui     the TUI — a thin shell over the same core
src/          latch-legacy (v1) — kept beside, frozen
docs/legacy/  v1 documentation, archived
```

v2 is the mainline (`latch`, released as 2.0.0). The v1 code stays in the
tree as the frozen `latch-legacy` package for reference; it is not built
by default and receives no changes.

## License

AGPL-3.0-or-later
