# latch v2 — Test Plan

What is proven, where, and how to run it. CI (`.github/workflows/ci.yml`)
runs fmt + clippy `-D warnings` + all of this on every push; red CI blocks
merge, no exceptions.

```
cargo test -p latch-core -p latch-cli -p latch-ui
```

The E2E suites run the **real git binary** against local bare repos
(`file://` origins) in tempdirs — real files, real subprocesses, mocked
keyring/prompt/clock. Nothing ever touches a real secrets repo (standing
rule 4). Expect a few minutes: Argon2id runs at production cost.

## Suites

### `envelope_tests.rs` (9) — the format can never drift
- Seal/open round-trips incl. binary + empty content; wrong key, wrong
  generation (`WrongKey` names what IS needed), flipped body/header bytes
  all fail authentication; **pinned byte-level regression vectors** for
  the envelope and the Argon2id KDF.

### `l1_credentials_tests.rs` (9) — K4 chain
- Resolution order env > file > keyring, proven with all three populated;
  file-backend round-trip incl. wrong-passphrase; hex env injection for
  binary slots; AR11 session cache honours TTL via the mock clock; M7:
  headless prompt paths are hard errors.

### `l2_sync_tests.rs` (6) — the sync loop, two machines
- Full round-trip: init → commit → push on A; raw clone of origin proves
  **ciphertext-only** (plaintext scan) and `LATCH2` magic; B pulls via
  hex-injected key; S4 push refusal + `--force` resolution (history
  intact); pull conflict + `--overwrite`; idempotent commit (no no-op
  re-encryptions); removal detection; wrong-key reporting; offline commit
  survives a later refresh (the bug the suite caught); origin tampering
  detected by verify and healed by rollback+push — never silently; W6 run
  injects into a real child with exit-code propagation; W7 template
  expansion in the child + strict unknown-reference error; W10 diff masked
  by default; W11 edit via scripted editor leaves zero residue; D3
  examples are keys-only.

### `l4b_group_tests.rs` (2) — W12 groups
- Founding commit with subscriber fan-out; single-copy storage proven at
  origin (group content once, stubs otherwise, all ciphertext);
  edit→fan-out; divergence hard error naming files and keys →
  `resolve --source`; all three W12c join routes incl. `adopt`; machine B:
  pull materializes members via group key, run() injects group vars into a
  real child, edit+commit on B recognized as a known member's change;
  all-empty founding = error.

### `l5_key_machine_tests.rs` (3) — keys & machines
- K3 rotation: old key refused on new ciphertexts, verify all-Ok, caveat
  in the outcome; K2 env keys: prod-only machine decrypts prod, dev fails
  with a clear key-missing report; K5 show hides without `--reveal`; K6
  backup (structure+content leak scan on the bytes) → wrong passphrase
  hard error → restore on a fresh machine pulls; M2: scoped clone leaves
  foreign keys behind, wrong verify code refused, offers single-use and
  expiring, ssh wrapper transcript replayed against a real target.

### `l7_lifecycle_tests.rs` (9) — lifecycle
- M5 state machine on scripted releases: happy path keeps `.prev`,
  checksum mismatch aborts untouched, non-executing binary aborts
  untouched, up-to-date short-circuits with zero downloads; M4 path
  honours the config override and checks `$PATH`; D5 bind refuses unknown
  names, rebind + pull works in a fresh dir, unbind keeps keys.

### `d8_ignore_tests.rs` (9) — what discovery may and may not see
- Against the **real filesystem and real git**, deliberately: the mock
  file backend has no ignore semantics, so every other suite is blind
  here — which is how the 2026-08-28 live bug (discovery honoured
  `.gitignore` and therefore skipped every `.env`) survived ~90 green
  tests. Gitignored `.env`, `.env.local` and `api/.env` are still found;
  a parent repo's `.gitignore` cannot hide a subproject's `.env`;
  `.latchignore` excludes what it names; the built-in directories are
  pruned and `!vendor/` lifts one; `discover_all` (the `--no-ignore`
  view) sees everything while normal discovery stays unchanged; the
  secrets clone listing is never filtered; `latch init` writes the
  starter file and never overwrites an existing one.

### core unit tests (9)
- Template engine (expansion, cycles, strict errors), discovery/flattening
  (bijective, `__` refused), M5 tag/sums parsing.

### `ui_tests.rs` (10) — the TUI, no terminal
- Dashboard/matrix/history/doctor snapshots from fixture worlds; **masked
  values provably absent from the render buffer** until per-row reveal;
  edit flow marks dirty and saving emits the core-backed command; S4
  conflict renders the choice dialog and only the explicit key maps to
  force/overwrite; rollback confirms then emits exactly the core call;
  login masks the PAT in the buffer; clone wizard scoping; tab cycling
  loads each screen's data.

### `completions_tests.rs` (1, cli)
- bash/zsh/fish generation against the real binary.

### `m7_surface_tests.rs` (2, cli) — the whole surface, headless
- Every user-reachable verb (except `update`, mock-covered in l7) runs
  against the real binary without a TTY under a hard timeout: it must
  complete or fail with a remedy line — a hang or a bare error fails the
  suite (M7). The D6 snapshot pins every `--help` text in
  `tests/snapshots/cli_surface.txt`; intentional surface changes are
  regenerated with `UPDATE_CLI_SNAPSHOT=1` and show up as a reviewable
  diff.

### `exec_tests.rs` (1, ui) — the Cmd→core mapping against real git
- World refresh (states, key cells, sources), commit/push mapping, save
  round-trip that really commits, masked diff, S4 push conflict surfacing
  as a Conflict op (and the deliberate force resolving it), history load,
  error mapping keeps the remedy, doctor snapshot.

### `d13_escrow_tests.rs` (4) — no publishing without a second copy
Real git. Push refuses under a key with no recorded escrow (naming key,
generation, remedy and flag) and nothing reaches the origin; `latch key
backup` records it in `_escrow/<label>.json` and unlocks the push; the
record provably carries no plaintext, key material or passphrase;
`--no-escrow` publishes but stays visible in state until a real escrow
lands; a rotated generation is refused until re-escrowed; the removal
note flips with whether a key that could read the history still exists.

### `d10_d11_tests.rs` (3) — single-file cat + duplicate rules
Real git. Raw `cat` byte-identical + plaintext-scan over latch home;
`--expand` resolves cross-file references strictly (unresolved → error);
duplicate names: same value merges, different values error naming both
files, `--last-wins` keeps the alphabetically last.

### `d9_project_remove_tests.rs` (3) — project removal
- E2E vs real git: remove sweeps every env's ciphertexts, other projects
  untouched, link+marker cleaned, keys KEPT and the kept key still opens
  the git history; wrong typed name refuses with nothing changed;
  headless without --yes is a hard error naming the flag, with --yes it
  works; --purge-keys empties the key slots; repo-wide list shows
  linked/unlinked correctly.

## Coverage measurement

CI's `coverage` job runs `cargo llvm-cov --summary-only` over the three
v2 crates on every push — informational, so the measured number is
always one click away and drift is visible. First measurement
(2026-08-12, run 31551173482): **73.9% lines · 76.6% regions · 69.9%
functions**. The uncovered remainder is dominated by CLI print arms and
real-platform adapters (keyring/terminal paths that only run live). Run locally with
`cargo llvm-cov -p latch-core -p latch-cli -p latch-ui --summary-only`
(needs `cargo install cargo-llvm-cov`).

## Standing rules

1. Red CI blocks merge.
2. Every live bug becomes a mocked test before the fix (see the refresh
   dirty-tree case in l2 — the pattern to follow).
3. Tests assert secrets never reach git, argv, logs or backups — the
   plaintext-scan assertions are not decorative; keep them in new tests.
4. Development runs against scratch repos only.
5. New features land with their feature-ID-tagged tests in the matching
   suite.

## Not covered by automation (by design)

- Real GitHub network paths (login validation, M5 against the live API) —
  covered manually at release time (R11).
- Real OS-keyring behaviour — the probe-based fallback is unit-tested;
  the live keyring path is exercised on desktops in daily use.
- L8 cutover of the real secrets repo — Kenny-gated, see
  REALIZATION_PLAN.md.
