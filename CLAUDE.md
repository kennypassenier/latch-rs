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
| Current phase | COMPLETE — all 11 phases closed (Form 4 retro, 2026-08-29) |
| Last completed gate | Form 4 · retrospective: R1/R2/R3/R6 adopted, ecosystem entry confirmed (see docs/REALIZATION_PLAN.md gate log) |
| Next gate | none — only the deferred Windows runtime check remains (Kenny-gated) |
| AFK mode | off |
| Build state | **v2.2.0 released** — tagged, signed, installed; D9 (2.1.0) + D10/D11 (2.2.0) shipped post-2.0; the homelab consumes `latch cat` (its D12) |

## Deferred to end-of-project (Kenny-gated)

- **Windows 11 runtime verification** — the Windows machine is only
  reachable at the end of the project. The code is cross-platform and CI
  builds it on windows-latest, but `docs/WINDOWS_TEST_CHECKLIST.md` must
  be run on the real Win11 machine before Windows is "verified". Do not
  treat Windows as runtime-confirmed until then.
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
- Discovery must never consult `.gitignore` (D8, 2026-08-28 mini-round):
  every project gitignores `.env`, and honouring it made latch silently
  skip the files it manages. Exclusions live in `.latchignore` plus the
  built-in list in `discovery::DEFAULT_IGNORED_DIRS`. Ignore semantics
  are only provable against the real filesystem — the mock file backend
  has none, which is how the bug survived ~90 green tests.
- Publishing a release (tag push) is always Kenny's explicit go.
- New direct dependencies need a mini-round with Kenny first (AR18);
  the MSRV (1.86, AR16) is raised only as a deliberate commit.
