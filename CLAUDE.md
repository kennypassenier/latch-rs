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
| Current phase | 7-10 · retro-fit pass (procedure formalized mid-project) |
| Last completed gate | evaluation form 2026-08-12: all 11 findings → Close |
| Next gate | approval form SCOPE/CLAUDE/INVENTORY; then tech-choice + critic mini-rounds; docs approval; release report ("Tag & release?" = Kenny's go); retro |
| AFK mode | off |
| Build state | L0-L9 done, 59 tests green, CI enforcing, v2.0.0-dev on `v2-redesign` |

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

Commits are blocked by `.claude/hooks/check-commit.sh` unless
`.claude/hooks/gates.sh` passes (fmt + clippy -D warnings + full test
suite over latch-core/cli/ui) and the message carries IDs in brackets
(`[W12]`, `[L4b]`, `[meta]`). CI re-runs the same gates on every push;
`main` has branch protection requiring the `gates` check, admins
included. The legacy package is deliberately ungated (AR14).

## Hard rules for this repo

- Real secrets never enter development: scratch repos only (standing
  rule 14). Test suites assert ciphertext-only origins — keep the
  plaintext-scan assertions in any new suite.
- The envelope byte format and KDF parameters are pinned by regression
  vectors in `envelope_tests.rs`; changing them is a format break and
  needs a mini-round.
- Publishing a release (tag push) is always Kenny's explicit go.
- New direct dependencies need a mini-round with Kenny first (AR18);
  the MSRV (1.86, AR16) is raised only as a deliberate commit.
