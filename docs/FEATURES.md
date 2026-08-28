# Feature registry — latch v2 redesign

Permanent IDs, used in commits and docs forever. Ratings by Kenny,
2026-08-11 (interactive rounds): **Must** · **Should** · **Could** ·
**Won't** (rated via the fixed form scale). Each feature carries test
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
- **Auto**: nested monorepo fixture → exact expected set; list-before-encrypt
  asserted in output; exclusion behaviour is D8's.

> **Amendment 2026-08-28 (mini-round, D1/D8).** The original acceptance
> criterion required `.gitignore`'d fixtures to be EXCLUDED. That was
> wrong and shipped as a live bug: every project gitignores `.env`, so
> discovery skipped exactly the files latch manages and `latch commit`
> reported "0 file(s)" as success. Exclusions now come from `.latchignore`
> and a built-in directory list only — never from git. See D8.

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

### D8 · `.latchignore` — **Must** *(added 2026-08-28 by mini-round)*
latch's own exclusion file, gitignore format including negations, read
only by latch. `.gitignore` is never consulted (see the D1 amendment).
Without any file, a built-in list is always skipped: `.git`, `.latch`,
`node_modules`, `target`, `vendor`, `.venv`, `venv` — otherwise the first
commit in a Node project offers dozens of third-party `.env` files. The
list is a floor, not a cage: a negation in the project-root `.latchignore`
(`!vendor/`) lifts an entry. `latch init` leaves a commented starter file
so the mechanism is discoverable in the project itself. `latch status
--no-ignore` lists what the rules are hiding (view only — a commit still
respects them), and finding zero env files prints a warning naming the
directory, the rules and that flag instead of reporting success.
- **Auto** (`d8_ignore_tests.rs`, real filesystem + real git — the mock
  file backend has no ignore semantics, which is why ~90 green tests
  missed the bug): gitignored `.env`/`.env.*`/`api/.env` still found; a
  parent repo's `.gitignore` cannot hide a subproject's `.env`;
  `.latchignore` excludes what it names; the built-in dirs are pruned;
  `!vendor/` lifts one; `discover_all` sees everything while normal
  discovery is unchanged; the secrets clone listing is never filtered;
  `latch init` writes the starter file and never overwrites an existing
  one. `.env.sample` joins `.env.example` as a template, not a secret
  (v1 parity, restored in the same round).

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

### M3 · ~~Clone groups~~ — withdrawn (mischaracterized)
Originally rated Could based on a WRONG description (machine-clone
bundles). The real v1 feature is the pragma-based file-group mechanism —
re-rated properly as **W12**. Machine-clone bundling as such is covered by
M2's scope flags.

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

## Proposed in the redesign round (rated 2026-08-11)

### K6 · Key backup / escrow export — **Must**
All project keys exported as one passphrase-encrypted file (or printable
text) for offline safekeeping — closes the "all machines lost = repo
forever unreadable" gap. `latch key backup` / `latch key restore`.
- **Auto**: backup → wipe credential store → restore → everything decrypts;
  wrong passphrase → hard error; backup content proven ciphertext-only.

### M7 · Non-interactive / CI mode — **Must**
Global `--yes`/non-interactive support + env-driven answers; without a TTY
every would-be prompt is a hard error, never a hang. The v1 sync-stall
lesson.
- **Auto**: every command run without TTY either completes or fails loudly
  (exhaustive over the CLI surface); no prompt path reachable.

### S6 · `latch verify` — repo-wide integrity audit — **Must**
Verify every remote ciphertext decrypts and authenticates with current
keys, manifest consistent, without writing anything.
- **Auto**: corrupt one remote file in the mock → verify names exactly that
  file; clean repo → exit 0.

### D7 · Shell completions — **Must**
clap-generated bash/zsh/fish completions.
- **Auto**: generation succeeds for all three shells (snapshot).

### S5 · Local cache + offline pull/run — **Should**
Every successful pull caches the ciphertexts locally; `latch run` and
`pull --offline` keep working through outages with a loud "using cached
state from N days ago". First pull still needs network.
- **Auto**: pull → kill network (mock) → run still injects; staleness
  warning asserted; cache is ciphertext-only.

### W10 · `latch diff` — **Should**
Masked-by-default diff (key names + changed/added/removed) between local,
committed, and remote; `--reveal` for values.
- **Auto**: golden diff output; values provably absent without --reveal.

### W12 · Linked file groups (pragma pattern) — **Should** *(design approved in full — see ARCHITECTURE_DECISIONS.md W12a-d)*
Multiple .env files (cross-project) share one encrypted content blob via a
first-line pragma `# latch:group=<name>`. Edit ONE member → commit updates
all members locally in the same commit. Empty members (pragma only) are
subscribers, never a valid change source. Two changed members = hard error
with explicit `latch group resolve --source` as the only choosing path.
Joining with differing content errors (empty-to-subscribe or
`group adopt`). Global per environment with per-group keys.
- **Auto**: one-changed-member commit fans out to all members incl. filling
  empty subscribers; baseline updated.
- **Auto**: two changed members → error naming files and keys; resolve
  --source wins; non-interactive mode never prompts.
- **Auto**: new member with differing content → error offering both
  remedies; adopt makes its content the group's.
- **Auto**: all-empty group with no prior content → "no content yet" error.
- **Auto**: group keys appear in K6 backups and M2 clone payloads.

### W11 · `latch edit` — **Should**
Decrypt → $EDITOR via tmpfs → auto-commit on close → optional push. Zero
plaintext ever on physical disk; interrupted edit leaves nothing behind.
- **Auto**: temp path is on tmpfs (or refused); simulated editor writes →
  new ciphertext committed; simulated crash → no residue.

### S7 · Second backend (local dir / rsync) — **Won't**
GitHub suffices; not worth the abstraction layer.

## G · Management client (proposed by Kenny, feature set rated 2026-08-11)

One interactive client managing the latch installation itself — a layer on
top of the same core the CLI uses, never a second implementation. Built on
the homelab TUI foundation: Elm-style, mockable backend, snapshot-tested,
AZERTY-aware. Technology choice (terminal TUI vs. GUI) = AR8.

### G1 · The management client (`latch ui`) — **Must**
- **Auto**: snapshot tests per screen against a scripted backend; the UI
  calls the same core functions as the CLI (no parallel logic — enforced
  by core owning all operations).

### G2 · Project dashboard — **Must**
All projects with sync state, linked dir, env count, last push/pull, key
presence; ENTER opens detail.
- **Auto**: snapshot with a fixture world (clean/modified/behind projects).

### G3 · Key & environment matrix — **Must**
Projects × environments grid: which key is present from which source
(keyring/file/env), what's missing on this machine.
- **Auto**: fixture with mixed sources renders correct per-cell markers.

### G4 · Secrets browser/editor — **Must**
Masked values (reveal per row), add/edit/remove variables, save = encrypted
commit via the W11 machinery; diff visible before push.
- **Auto**: values never in the render buffer unless revealed; edit →
  commit round-trip against mock backend.

### G5 · Sync operations from the client — **Must**
One-key commit/push/pull/diff with live progress; S4 conflicts become an
interactive choice (pull first / view diff / overwrite deliberately).
- **Auto**: conflict fixture → choice dialog rendered, no silent overwrite.

### G6 · History browser + rollback — **Must**
Version list (when, which files), masked diff against now, rollback with
confirmation.
- **Auto**: fixture history renders; rollback emits the right core call.

### G7 · Machine-clone wizard — **Should**
Guided M2: target, scope, verify-code, progress, end-check.

### G8 · Doctor & verify panel — **Should**
W8 state + one-key S6 audit, per-file green/red with remedy.

### G9 · Onboarding & admin flows — **Should**
Guided login (M1, live validation), project linking (W1), rotation with
consequences explained (K3), key backup/restore (K6).

---
Final tally: 29 Must · 13 Should · 0 Could · 2 Won't + 1 withdrawn (45 entries).
Next: architecture decisions (phase 3), then testing & documentation
(phase 4).
