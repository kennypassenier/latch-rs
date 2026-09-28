# latch

Encrypted `.env` secrets management backed by a private GitHub
repository — v2 is a ground-up Rust rewrite (workspace `crates/`),
v1 is frozen beside it as `latch-legacy` (`src/`).

This project follows the dev procedure in `~/Projects/dev-procedure/`
(`/project-flow`). Standing rules apply to every change:
`~/Projects/dev-procedure/STANDING_RULES.md`.

## Procedure status

| Field | Value |
|---|---|
| Current phase | COMPLETE — reopened by mini-round D13/D14 (2026-09-02, key loss) and by M4 (2026-09-26, durable credentials) |
| Last completed gate | Form 4 · retrospective: R1/R2/R3/R6 adopted, ecosystem entry confirmed (see docs/REALIZATION_PLAN.md gate log) |
| Next gate | M4 mini-round form (durable credential file as primary store) |
| AFK mode | off |
| Build state | **v2.6.0 released + signed 2026-09-28** (feat-put-1: `latch put`, `cat --project`), installed on WSL through `latch update` (byte-identical to the release asset). ws-tools keeps latch on the signed release on Garuda and WSL. Windows runtime-verified 2026-09-27 |
| Next action | waiting on Kenny: booting Garuda once and running `resume` there, so ws-tools brings Garuda's latch to the signed release; then Claude retires ~/.secrets/latch/env and reads `latch state` without env after a reboot into the other OS — that closes M4. feat-put-1 closes when the homelab dashboard's first real `latch put` leaves the other files of that env unchanged |

## Deferred to end-of-project (Kenny-gated)

- ~~**Windows 11 runtime verification**~~ — done 2026-09-27 on
  DESKTOP-KENNY with the signed 2.5.1/2.5.2 (run log in
  `docs/WINDOWS_TEST_CHECKLIST.md`); four Windows faults found and fixed on
  the way (fix-win-keyring-1, fix-win-paths-1, fix-remove-escrow-1,
  fix-win-update-1). Not run: `clone --to` from Windows, the §5 tamper test.
- ~~**RELEASE_PUBKEY**~~ — done: the real minisign public key is baked
  into `crates/core/src/ops/update.rs` (commit a39fe19). Every release
  still needs `scripts/sign-release.sh <tag>` afterwards, or
  `latch update` refuses it.

Historical note: phases 0-9 ran de facto during the v2 rewrite (forms
for features and architecture, milestones L0-L9, hardening audit,
docs); the procedure repo was formalized from this project and homelab
v2. The 2026-08-12 evaluation retro-fits the missing artifacts and
gates — see the form outcome in this file's git history.

## Project documents

| Doc | Purpose |
|---|---|
| docs/SCOPE.md | goals, non-goals, success criteria, constraints (Phase 0, reconstructed) |
| docs/INVENTORY.md | v1 feature inventory that seeded Phase 2 (reconstructed) |
| docs/FEATURES.md | rated feature list with permanent IDs (Phase 2, frozen) |
| docs/ARCHITECTURE_DECISIONS.md | frozen AR decisions incl. tech choice (Phases 3-4) |
| docs/REALIZATION_PLAN.md | milestones L0-L9 + status table (Phase 5) |
| docs/TEST_PLAN.md | what is proven where + accepted limitations (Phase 7) |
| docs/USER_GUIDE.md, DEBUGGING_GUIDE.md, OPERATIONS_RUNBOOK.md, ARCHITECTURE_REFERENCE.md | Phase 8 set |
| docs/legacy/ | archived v1 documentation |

## Gates (enforced)

Two layers run the same two gates: `.claude/hooks/gates.sh` (fmt +
clippy -D warnings + full test suite over latch-core/cli/ui) and IDs in
brackets in the message (`[W12]`, `[L4b]`, `[meta]`).

- **`.githooks/pre-commit` + `.githooks/commit-msg` — the primary gate**,
  because git hooks are repo-scoped: they fire for every commit from any
  session, terminal or tool. Activated with `git config core.hooksPath
  .githooks` (local config, so a fresh clone repeats that one command —
  documented for humans in the README and OPERATIONS_RUNBOOK R13).
- `.claude/hooks/check-commit.sh` — PreToolUse hook on Bash: the same
  two gates for sessions opened in this directory. A second layer, no
  longer the only one (it was, until 2026-08-30).

CI re-runs the same gates on every push; `main` has branch protection
requiring the `gates` check, admins included. The legacy package is
deliberately ungated (AR14).

## Hard rules for this repo

- Real secrets never enter development: scratch repos only (standing
  rule 14). Test suites assert ciphertext-only origins — keep the
  plaintext-scan assertions in any new suite.
- The envelope byte format and KDF parameters are pinned by regression
  vectors in `envelope_tests.rs`; changing them is a format break and
  needs a mini-round.
- Discovery must never consult `.gitignore` (D8, 2026-08-28 mini-round):
  every project gitignores `.env`, and honouring it made latch silently
  skip the files it manages. Exclusions live in `.latchignore` plus the
  built-in list in `discovery::DEFAULT_IGNORED_DIRS`. Ignore semantics
  are only provable against the real filesystem — the mock file backend
  has none, which is how the bug survived ~90 green tests.
- Publishing a release (tag push) is always Kenny's explicit go.
- New direct dependencies need a mini-round with Kenny first (AR18);
  the MSRV (1.86, AR16) is raised only as a deliberate commit.
