# Architecture decisions — latch v2

Decided with Kenny in interactive rounds, 2026-08-11/12. Permanent IDs;
referenced in commits. The *why* is recorded per decision.

## AR1 · Workspace: core + cli + ui
`latch-core` holds ALL logic behind backend traits with zero ambient I/O —
every test runs against mocks that record calls. `latch` (CLI) and the TUI
are thin shells over the same core; the UI can never grow a second
implementation of anything. *(Why: the blob-corruption bug survived months
because the GitHub path wasn't mockable; homelab proved the pattern.)*

## AR2 · Storage backend: local git clone via the git binary
Latch maintains a hidden clone in `~/.latch/repo` and drives real git.
Push = encrypt into clone + `git add/commit/push`; history = `git log`;
rollback = `git checkout <ref>`; overwrite protection = git's own
non-fast-forward refusal; offline cache = the clone itself. *(Why: the
entire "API returns something slightly different" bug class — June's
binary-blob corruption — becomes impossible; S3/S4/S5 come nearly free.)*

## AR3 · Credential file: one passphrase, own XChaCha format
`~/.latch/credentials.enc`: all credentials in one file, XChaCha20-Poly1305
with an Argon2-derived key from a single passphrase. Same format serves K6
key backups. *(Why: one code path, no extra dependencies, consistent with
the secrets crypto.)*

## AR4 · v1 migration: clean break
The secrets repo is refilled fresh from working machines; v2 never parses
v1 formats. Old history remains in git as an archive. *(Kenny's call:
simplest; the old repo stays readable with v1 if ever needed.)*

## AR5 · Machine clone: `latch clone --to <ssh>` wrapper + subcommands
One command runs the whole offer/payload/apply dance over ssh, with scope
flags `--project` / `--env` (whole setup by default). The manual
offer/create/apply subcommands remain for air-gapped/bootstrap cases.

## AR6 · Failure model: homelab style
Every error carries a remedy line; all writes are atomic (temp + rename);
pull is all-or-nothing (one corrupt file → nothing written); without a TTY
any would-be prompt is a hard error (M7); `RUST_LOG` reveals underlying
operations; `latch state` is the doctor.

## AR7 · Test & release standard: homelab grade
Mock-backend tests on every destructive path; pinned regression vectors for
the crypto format; CLI-surface and TUI snapshots; CI gates (fmt, clippy -D
warnings, tests) where red blocks merge; tagged releases with sha256
checksums feeding M5 self-update; every live bug becomes a test first.

## AR8 · Client technology: terminal TUI (ratatui)
The homelab recipe: Elm-style model, mockable backend, snapshot tests,
AZERTY-aware keys, effect levels. A GUI can come later on the same core.

## AR9 · Repo layout: pure path convention, self-describing
`<project>/<env>/<flattened-name>.enc`; the git tree is the index. No
manifest file. Group members are stored as tiny encrypted files containing
only their pragma line; group content lives once in
`_groups/<env>/<name>.enc`. Nothing exists that can drift out of sync with
the tree. *(Why: v1's manifest-vs-reality drift was one of the reliability
bugs that got groups disabled.)*

## AR10 · Ciphertext envelope: full header
`LATCH2` magic + format version + key-id (which key, which rotation
generation) + nonce, then ciphertext. *(Why: precise errors — "encrypted
with prod key gen 3, you have gen 2" instead of "decryption failed" — plus
a forever migration path; S6 verify can report per-file key needs.)*

## AR11 · Passphrase sessions: tmpfs cache with TTL
First unlock caches the opened credentials in `/run/user/…` (RAM, gone at
reboot) with a configurable TTL (default 15 min; 0 = always prompt).
Scripts use env injection and never touch the cache. *(sudo-like balance
of safety and sanity.)*

## AR12 · Concurrency: file lock around mutations
Mutating operations take `~/.latch/lock`; a second process waits with a
message and times out with a clear error. Reads stay lock-free. *(TUI +
cron will coexist; a half-committed repo is not an acceptable failure.)*

## AR13 · Templates: expand at use
The repo stores raw `${VAR}` references; expansion happens at pull/run
output. Unresolved reference or cycle = hard error naming the variable.

## AR14 · Rebuild approach: alongside the old code
New workspace grows next to `src/`; old code stays as reference until the
new one proves parity, then is archived in one closing pass (homelab
legacy pattern).

## AR15 · Config: one `~/.latch` dir + overrides
TOML config in `~/.latch/` together with credentials, repo clone and cache
— one dir that K6 backup and M2 clone can reason about. `LATCH_HOME` and
an XDG-layout flag override for those who want it.

## W12 · File groups design (approved in full)
- **Cycle (W12a)**: membership via first-line pragma
  `# latch:group=<name>`. Latch keeps a local baseline fingerprint per
  group. At commit: empty members (pragma only) never count as changes;
  exactly one changed member becomes the new group content and ALL other
  members are updated locally in that same commit; all-empty with no
  content = error.
- **Divergence (W12b)**: two or more changed members = hard error naming
  files and differing keys; the only choosing path is explicit:
  `latch group resolve <name> --source <file>`. Never interactive.
- **Joining (W12c)**: three valid routes — empty+pragma subscribes;
  pragma+identical content joins silently; pragma+different content on a
  new member errors with both intents in the remedy (`empty the file to
  subscribe, or latch group adopt <name> --from <file>`).
- **Scope (W12d)**: global per environment (cross-project), each group
  encrypted with its own auto-created group key, included in K6 backups
  and M2 clones.

## Tech-choice record (Phase 3, decided 2026-08-12 in the retro-fit gate)

## AR16 · MSRV: pinned at 1.86, CI-verified
`rust-version = "1.86"` in the workspace (the highest requirement in the
non-WASI dependency graph; matches the legacy pin). CI builds the three
v2 crates with exactly that toolchain — a dependency bump that raises
the bar turns red in CI instead of failing on an older machine later.
Raising the MSRV is a deliberate commit, never a side effect.

## AR17 · Platform scope: Linux AND Windows (amended 2026-08-12)
Originally recorded as Linux-only; corrected the same day — Kenny runs
both Garuda Linux and Windows 11, so both are first-class targets. The
release ships two assets (x86_64 linux-gnu and x86_64-pc-windows-msvc);
the self-updater (M5) picks the one for its own OS. Platform-specific
code is `#[cfg]`-gated behind the platform traits: file modes are Unix
0600/0700, on Windows privacy comes from the per-user profile directory's
NTFS ACLs; core-dump hardening is Linux-only. Two features degrade on
Windows by design: W11 zero-disk edit is UNAVAILABLE (no tmpfs; it
refuses rather than weaken the never-touch-disk guarantee — WA), and the
AR11 session cache is OFF (the Credential Manager covers key storage —
WB). macOS is still not a target. Runtime verification on Windows is done
on Kenny's machine (docs/WINDOWS_TEST_CHECKLIST.md); the CI build only
proves it compiles for the Windows target.

## AR18 · Dependency policy: formally conservative
~13 direct dependencies in core, all established crates; network I/O
deliberately via the system git/curl binaries instead of an HTTP stack.
Adding a NEW direct dependency to any v2 crate requires a mini-round
with Kenny first (supply-chain surface is a decision, not a default).
Routine version bumps of existing dependencies stay free.

Direct deps added under an approved feature (recorded here for the paper
trail): `zeroize` and `libc` (K1 memory hardening — both were already
transitive via the crypto crates, so no new supply-chain surface);
`minisign-verify` (D4 release-signature verification — small,
purpose-built, verify-only).

## AR20 · Self-update authenticity: minisign signature (D4)
The checksum manifest (`SHA256SUMS`) must carry a valid minisign
signature under a public key baked into the binary (`RELEASE_PUBKEY`)
before ANY downloaded byte is trusted — a compromised GitHub account
cannot forge it without the offline secret key. Signing happens LOCALLY
(Kenny, `scripts/sign-release.*`), never in CI, so the secret key never
touches GitHub. The updater also refuses to move to a version that is not
strictly newer (downgrade guard), and fails CLOSED when no valid key is
configured. See OPERATIONS_RUNBOOK R11.

## AR19 · License: AGPL-3.0-or-later confirmed
Inherited from v1, now an explicit decision for v2. Anyone modifying
latch and offering it as a network service must publish their changes;
for personal use nothing changes.
