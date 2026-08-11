# Feature registry — latch v2 redesign

Permanent IDs, used in commits and docs forever. Ratings by Kenny,
2026-08-11 (interactive rounds): **Must** (onmisbaar) · **Should** (gewenst)
· **Could** (later) · **Won't** (niet doen). Each feature carries test
scenarios; design notes record constraints agreed during rating.

## K · Keys & crypto

### K1 · Authenticated encryption (XChaCha20-Poly1305) — **Must**
Per-file AEAD encryption; any ciphertext tampering or truncation is detected
before decryption ever writes a byte.
- **Auto**: round-trip vector tests; flipped-bit/truncated ciphertext →
  hard integrity error, no partial output file.
- **Auto**: regression vectors pinned (existing `regression_vectors.rs`
  carries over) so a refactor can never silently change the format.

### K2 · Multi-key environments — **Should**
Optional per-environment keys (`<project>.key.<env>`) isolating blast
radius between e.g. dev and prod.
- **Auto**: pull with only the dev key present → dev files decrypt, prod
  files are skipped with a clear "key missing" report, exit code reflects it.

### K3 · Key rotation — **Must**
New project key + re-encrypt everything; documented caveat: git history
stays readable with the old key, so full remediation also rotates the
underlying secrets.
- **Auto**: rotate → all files decrypt with new key only; old key fails
  with integrity/key error on the new ciphertexts.
- **Docs**: the history caveat is stated in the user guide and in the
  command's own output.

### K4 · Credential storage that works everywhere — **Must** *(redesigned)*
**Agreed model: keyring + encrypted-file fallback + env override.** OS
keyring where a Secret Service exists (desktop); otherwise a single
Argon2-passphrase-encrypted file (`~/.latch/credentials.enc`), unlocked via
prompt or `LATCH_PASSPHRASE`; `LATCH_*` environment variables always win
(orchestrator injection, e.g. the homelab host vault). Same commands
everywhere — this replaces keyring-only, which failed on Kenny's LXCs.
- **Auto**: resolution order test — env beats file beats keyring; missing
  everything → clear error naming all three options.
- **Auto**: file backend round-trip incl. wrong-passphrase error path.
- **Manual**: full workflow on a keyringless LXC using only the file
  backend, and only env injection.

### K5 · Key inspection/export (`latch key`) — **Should**
Show/export a project key (for offline safekeeping).
- **Auto**: export never prints to a terminal without an explicit
  `--reveal`-style acknowledgement.

## S · Storage & sync

### S1 · GitHub repo as storage backend — **Must**
Private repo holds ciphertexts only. *(Architecture phase: git-API vs. real
`git` — the recent blob-corruption bugs argue for revisiting.)*
- **Auto**: push/pull round-trip against a mocked backend, including binary
  content (the bug class just fixed: blob-by-sha path).
- **Auto**: no plaintext ever in any request body (assertion on the mock).

### S2 · Manifest / repo index — **Must**
Maps projects and encrypted files to local paths; multiple projects share
one repo without collisions. Form (JSON file vs. path convention) is an
architecture decision.
- **Auto**: two projects, overlapping filenames → no collision; pull
  restores each to its own tree.

### S3 · Versioning: history + rollback — **Must**
`latch history` lists secret versions; `latch rollback <ref>` restores one.
- **Auto**: three pushes → history shows three; rollback to v1 → pull
  yields v1 content; rollback to unknown ref → clear error.

### S4 · Overwrite protection — **Must**
Push refuses when remote moved past your base (pull first or `--force`);
pull warns before clobbering uncommitted local changes.
- **Auto**: simulated concurrent push → refusal with remedy text; `--force`
  succeeds; pull-over-modified-local prompts (or refuses with flag in
  non-interactive mode).

## W · Workflow

### W1 · `latch init` — **Must**
Link a directory to a project; create or reuse its key.
- **Auto**: init twice is idempotent; init in a subdir of a linked project
  is detected and refused with guidance.

### W2 · `latch commit` (offline encrypt) — **Must**
Three-step model stays: commit encrypts locally without network.
- **Auto**: commit with network mocked away entirely still succeeds.

### W3 · `latch push` — **Must**
Upload staged ciphertexts (with S4 guard).
- **Auto**: push without prior commit → clear "nothing staged" message.

### W4 · `latch pull` — **Must**
Download, verify (K1), decrypt, place files (with S4 warning).
- **Auto**: full pull round-trip; tampered remote file → abort before any
  file is written (all-or-nothing).

### W5 · `latch status` — **Must**
Local vs. committed vs. remote, per environment — git-status for secrets.
- **Auto**: golden output for clean/modified/behind states.

### W6 · `latch run` (zero-disk injection) — **Must**
Inject secrets into a subprocess env; nothing touches disk.
- **Auto**: child sees variables; no temp files created (fs watch in test);
  exit code of the child is propagated.

### W7 · Template expansion — **Should**
`${VAR}` references resolved at pull/run. Strict mode: an unresolved
placeholder is a hard error, never silently left in place.
- **Auto**: chain expansion, escaping, cycle detection → error; unresolved
  → error naming the variable.

### W8 · `latch state` / doctor — **Should** *(reborn as diagnosis)*
Where does every credential come from (env/file/keyring), what's missing,
plus a one-shot pull command for another machine. The F6-doctor of latch.
- **Auto**: missing project key → report names exactly what's absent and
  how to fix it.

### W9 · `latch reset` — **Should**
Wipe local latch state for a project; remote and keys untouched.
- **Auto**: reset then pull reproduces a clean working state.

## D · Discovery & DX

### D1 · Automatic .env discovery — **Must**
Find all .env files in the tree (ignore-aware). **The file list is shown
before anything is encrypted** (no surprise pickups).
- **Auto**: nested monorepo fixture → exact expected set; .gitignore'd
  fixtures excluded; list-before-encrypt asserted in output.

### D2 · Path flattening — **Must**
Nested paths ↔ flat repo names, collision-free, reversible.
- **Auto**: property-style test — flatten/unflatten round-trips arbitrary
  relative paths; crafted collision pairs → explicit error.

### D3 · .env.example generation — **Must** *(behind an explicit flag)*
Keys-only example files — **only via an explicit flag** (e.g.
`--write-examples`), never as default side effect (Kenny's constraint).
- **Auto**: default commit produces no example files; with the flag, values
  are provably absent from output.

### D4 · Config layers (global + project) — **Must**
`~/.latch/config.toml` + per-project settings; metadata only, no secrets.
- **Auto**: config round-trip; secret-shaped values in config → refused.

### D5 · `latch project` management — **Should**
List/bind/unbind projects to directories.
- **Auto**: bind existing project to fresh dir → pull works there.

### D6 · CLI foundation — **Must**
clap skeleton, confirmations for destructive actions, progress bars,
consistent exit codes, and homelab-style error messages **with a remedy
line** on every failure.
- **Auto**: CLI surface snapshot test (help texts); every error type
  carries a remedy (exhaustive match test).

## M · Machine & lifecycle

### M1 · `latch login` — **Must** *(now with validation)*
PAT + repo setup, stored via K4; immediately validates that the PAT works
and the repo exists, failing loudly if not.
- **Auto**: invalid PAT/repo → specific errors; valid → stored via K4
  resolution model.

### M2 · Machine clone — **Must** *(redesigned: one command, scoped)*
E2E-encrypted state transfer, redesigned to **one command with scope
arguments**: whole setup, one project, or one environment of a project
(exact CLI shape decided in the architecture phase; the X25519
offer/payload machinery stays under the hood, pipeable over ssh).
- **Auto**: full/project/env scopes transfer exactly their slice, nothing
  more (assert absent keys on target); expired offer → clean retry path;
  wrong verify-code → refusal.

### M3 · Clone groups — **Could**
Saved named bundles for M2. Currently disabled for reliability; rebuild
only after the redesigned M2 is proven. Scope filters cover the need
meanwhile.

### M4 · `latch path` — **Should**
Managed install path + PATH guidance for M5.
- **Auto**: path resolution honors config override.

### M5 · `latch update` — **Must** *(homelab-grade)*
Self-update from GitHub Releases with the H5 lessons: checksum
verification against the release manifest, keep the previous binary,
verify the new binary runs (`--version`) before replacing.
- **Auto**: state machine tests with fake release: bad checksum → abort;
  non-executing binary → abort, old binary intact.

### M6 · APT repository — **Won't**
GitHub Releases + M5 cover distribution; not worth hosting a signed repo.

---
Tally: 18 Must · 6 Should · 1 Could · 1 Won't. Next: Claude's proposed
features (phase 2), then architecture decisions (phase 3).
