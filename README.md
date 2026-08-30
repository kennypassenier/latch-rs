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

## Development — enable the commit gates first

The gates are enforced by git hooks in `.githooks/`, and `core.hooksPath`
is **local config that a clone cannot carry**. So every fresh clone runs
this one command before its first commit, or it has no enforcement at
all and nothing will say so:

```
git config core.hooksPath .githooks
```

(`make install-hooks` does the same and marks the hooks executable.)

From then on every commit in this repository — any session, any
terminal, any tool — is refused unless `cargo fmt --check`, `cargo
clippy --all-targets -D warnings` and the full test suite pass over
`latch-core`/`latch-cli`/`latch-ui`, and the message names the feature
IDs it implements (`[W12, AR9]`, `[meta]` for infrastructure). The
frozen legacy package is deliberately ungated (AR14).

The Claude Code hook in `.claude/settings.json` runs the same two gates,
but only for sessions opened in this directory; the git hooks are the
layer that holds everywhere else. Procedure: [OPERATIONS_RUNBOOK
R13](docs/OPERATIONS_RUNBOOK.md).

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

v2 lives on this branch as `latch`; the v1 binary remains available as
`latch-legacy` until the cutover completes.

## License

AGPL-3.0-or-later
