# latch v2 — Architecture Reference

The *why* behind every structure. Decision IDs (AR1–AR15) are specified in
`ARCHITECTURE_DECISIONS.md`; this document describes the system as built.

---

## 1 · Workspace shape (AR1, AR4, AR14)

```
crates/
  core/   latch-core  — ALL domain logic, zero ambient I/O
  cli/    latch       — thin shell: parse args, call core, print
  ui/     latch-ui    — thin shell: Elm-style TUI over the same core
src/      latch-legacy — v1, kept beside, untouched (AR14)
```

**The AR1 rule:** core never touches `std::env`, `std::fs`, processes,
clocks or the network directly. Every effect goes through the `Platform`
bundle of traits (`Env`, `Files`, `Keyring`, `Prompt`, `Clock`, `Proc`) —
`platform/real.rs` holds the single production implementation,
`platform/mock.rs` the scripted doubles. This is why every destructive
path has a test: the whole world is injectable, including time and
subprocess output.

Shells contain no decisions. The TUI's `exec.rs` and the CLI's match arms
call the *same* `ops::*` functions; a feature exists exactly once.

## 2 · Storage: a real git clone (AR2, S1–S5)

`~/.latch/repo` is a normal clone of the private secrets repo, driven
through the real `git` binary:

- push = encrypt into the working tree + `add/commit/push`
- history (S3) = `git log`; rollback = `git checkout <ref> -- path`
- overwrite protection (S4) = git's own non-fast-forward refusal
- offline cache (S5) = the clone itself
- `--force` = `reset --soft origin/main` + commit on top — **history is
  never rewritten**, "force" only decides whose content is newest
- refresh never hard-resets a dirty clone — committed-but-unpushed work
  survives offline round-trips (regression-tested)

Auth travels as an `http.extraHeader` via `GIT_CONFIG_*` environment
variables — the token never appears in argv or in the clone's config file.

### Repo layout (AR9, D2)

```
<project>/<env>/<flattened>.enc     # api/.env → api__.env.enc  ('/' → '__', bijective)
_groups/<env>/<name>.enc            # W12 group content, stored once
```

Flattening refuses paths containing `__` — a rare loud error beats a
silent collision. Every file is self-describing: its envelope header names
the key that opens it.

## 3 · Envelope format (AR10)

```
LATCH2 · version(0x02) · keyid_len · key-id label · generation u16 LE ·
24-byte nonce · XChaCha20-Poly1305 ciphertext
```

The **entire header is AEAD associated data**: flipping any header byte —
including the key label — fails authentication. `peek_key_id` reads the
header without decrypting (verify, error reporting); a mismatched key
reports `WrongKey { needed, generation }` before any decryption is
attempted. Pinned regression vectors in `envelope_tests.rs` freeze the
byte format — it can never drift silently.

Keys are 32 random bytes, stored as `generation(u16 LE) || key` in the
credential chain. KDF for passphrase-derived keys (credential file, K6
backups) is Argon2id, 64 MiB / 3 passes / 1 lane, 16-byte salt — pinned by
regression vectors too.

## 4 · Credential chain (K4, AR3, AR11)

`env → encrypted file → OS keyring`, resolution in that order; writes go
to keyring where available, else the file. One code path everywhere — the
design that replaced v1's keyring-only approach that failed on LXCs.

- Slot names: `pat`, `key:<project>`, `key:<project>.<env>`,
  `group:<name>.<env>`; env-var form is `LATCH_` + slot with
  `:`/`.`/`-` → `_`, binary slots hex-encoded.
- The file is one AR10 envelope over a JSON slot map; the salt sits ahead
  of it (tampering changes the derived key → authentication fails).

**What "OS keyring" actually means on Linux, and why it is not storage
(established 2026-09-02, the hard way).** latch builds `keyring` v3 with
the `linux-native` feature, which is `linux-keyutils`: the **kernel**
keyring, not the desktop wallet. Entries appear as
`user: keyring-rs:key:<project>@latch` under the session keyring and are
linked into `_persistent.<uid>`. Two properties follow, and neither is
obvious from the phrase "OS keyring":

- A new login session gets a NEW session keyring. The persistent one
  still holds the keys but is not attached until something asks for it:
  `keyctl get_persistent @s`. Until then latch reports the key as
  missing, which is what made an upgrade look like data loss.
- The persistent keyring EXPIRES after a period of no access —
  `/proc/sys/kernel/keys/persistent_keyring_expiry`, 259200 seconds
  (three days) on this machine. A key nobody touches for a long weekend
  can genuinely be gone.

The keyring is also **machine-wide, not home-wide**, which `LATCH_HOME`
did not say: until D16 every home read the same drawer, so a scratch
home saw the machine's real keys. The namespace now follows the resolved
home — default stays `latch`, anything else becomes `latch@<home>`.

So the keyring is a convenience cache with a timer, and the durable
copies are the encrypted credential file (this chain's middle tier) and
the K6 escrow — which is why D13 makes publishing depend on an escrow
existing rather than trusting the keyring. Confidentiality is not
durability; the keyring only ever provided the first.
- AR11: the derived key is cached on tmpfs for 15 min so interactive use
  prompts once, not per command. No tmpfs → no cache, never a disk file.

Per-env keys (K2) resolve before the project key; they are only created
explicitly (`key rotate --env`) so a commit can never silently fork a key.

## 5 · Groups (W12)

Membership is data (`# latch:group=<name>` first line), not config.
Content lives once under a group key; member entries in project prefixes
are pragma-only stubs, so the layout stays self-describing and a project
pull knows exactly what it is looking at.

The commit-time engine classifies each member against a **local baseline**
(`groups.json`: content fingerprint + known-member set — per machine,
never in git):

| member state | classification |
|---|---|
| empty (pragma only) | subscriber — filled at fan-out, never a change |
| equals current content | in sync |
| equals baseline fingerprint | stale — fan-out updates it |
| known member, new content | change candidate |
| unknown member, new content | W12c join conflict (explicit adopt required) |

0 candidates → fan-out only · 1 → new content, everyone rewritten in the
same commit · ≥2 distinct → hard error naming files and differing keys;
only `group resolve --source` chooses. Pull registers the baseline so the
pull→edit→commit flow on a second machine classifies correctly.

## 6 · Machine clone (M2, AR5)

X25519 offer/payload: the target mints an ephemeral keypair (secret kept
0600, 15-minute TTL, single use), the source seals a JSON slot map to the
shared secret (transport key = SHA-256 over shared ∥ both publics), and a
6-digit code derived from **both public keys** must be confirmed at apply
— the MITM check, `--code` required headless. The `--to <ssh>` wrapper
drives offer→create→apply remotely; the payload is ciphertext and
argv-safe. Scope filters select slots; a project's group keys are found by
reading its stubs' pragmas.

## 7 · Failure model (AR6, M7)

- Every error carries a remedy after `::` — enforced by the `LatchError`
  type shape, not by discipline.
- All writes are atomic (temp + rename, 0600).
- Pull is all-or-nothing; one bad envelope writes zero files.
- No TTY ⇒ every would-be prompt is a hard error naming its answer
  (flag/env var). Hanging on hidden input — the v1 sync-stall bug class —
  is unrepresentable.
- One mutation at a time: an exclusive lock file with 15-minute
  stale-break guards commit/push/pull/edit/rotate/rollback.

## 8 · Self-update (M5)

curl (via the injected `Proc`) fetches release metadata → `SHA256SUMS` →
binary. Two gates before anything is replaced: manifest checksum match,
and the staged binary must execute `--version` and name the release. The
previous binary is kept at `<exe>.prev`. Every abort path leaves the
install byte-identical — the whole state machine runs against scripted
responses in tests.

## 9 · The TUI (G-series, AR8)

Strict Elm: `model` (plain data) ← `update` (pure, returns `Cmd`s) →
`exec` (the only core caller) → `view` (pure render). Tests build fixture
models, feed key messages, assert emitted commands, and snapshot the
render buffer on a `TestBackend` — including the guarantee that masked
secret values never enter the buffer at all (G4). Keybinds avoid the
number row (AZERTY).

## 10 · Testing standard (AR7)

See `TEST_PLAN.md`. The short version: pinned format vectors; mock-driven
tests on every destructive path; E2E suites that run the real git binary
against local bare repos with multi-machine scenarios; UI snapshots; and
the standing rule that every live bug becomes a mocked test before its
fix.
