# Realization plan — latch v2

Milestones build bottom-up: crypto first (everything depends on it), the
TUI when the core it displays exists, docs last (Kenny's standing order).
Every milestone lands fully tested per AR7; feature IDs in every commit.

## L0 · Foundations
Workspace (core/cli/ui per AR1) beside the old code (AR14). CI gates: fmt,
clippy -D warnings, tests — red blocks merge from day one. Crypto core:
AR10 envelope (magic, version, key-id, nonce), K1 encrypt/decrypt, pinned
regression vectors. Error type with remedy lines (AR6).

## L1 · Identity & credentials
K4 resolution (env > file > keyring) with the AR3 credential file and AR11
TTL session cache; M1 login with live PAT/repo validation; D4 config in
~/.latch (AR15); M7 non-interactive mode wired into everything from the
start; AR12 file lock.

## L2 · The sync loop (first end-to-end sliver)
AR2 git-clone backend; W1 init; D1 discovery (list before encrypt) + D2
reversible flattening (AR9 layout); W2 commit; W3 push / W4 pull with S4
protection (git non-fast-forward + local-changes warning); W5 status.
**Milestone exit: a real round-trip against a scratch GitHub repo.**

## L3 · Consumption & diagnosis
W6 run (zero-disk injection); W8 state/doctor; S6 verify; S3
history/rollback (git log/checkout mapping); W9 reset; S5 offline behavior
surfaced (the clone is the cache — flags + staleness warnings).

## L4 · Editing & groups
W7 templates (AR13, strict); W10 diff (masked); W11 edit (tmpfs); D3
example generation behind its flag; **W12 groups per the approved design**
(the reliability-critical one — full test matrix from FEATURES.md).

## L5 · Keys & machines
K2 env keys; K3 rotate; K5 key show; K6 backup/restore; M2 clone with the
AR5 --to wrapper and scope flags (group keys included).

## L6 · The management client
G1 TUI foundation (Elm, mock backend, snapshots, AZERTY) → G2 dashboard →
G5 sync ops → G4 secrets editor → G3 matrix → G6 history. Then G7-G9
(wizard, doctor panel, admin flows).

## L7 · Lifecycle
M5 self-update (checksums, keep previous binary, verify before replace);
M4 path; D7 completions; D5 project management; release workflow (AR7).

## L8 · Cutover (per-step go from Kenny)
AR4 clean break: fresh repo filled from Kenny's machines; his machines
migrate one by one (desktop first, LXCs via M2/env-injection); old code
archived (AR14 closing pass); v1 repo left as read-only archive.

## L9 · Documentation (last, per Kenny's order)
USER_GUIDE (per feature ID), DEBUGGING_GUIDE (evidence trail +
symptom→cause), OPERATIONS_RUNBOOK, ARCHITECTURE_REFERENCE, README honesty
pass, TEST_PLAN maintained throughout, legacy docs archived.

## Standing rules (from L0, forever)
1. Red CI blocks merge — no exceptions.
2. Every live bug becomes a mocked test before the fix.
3. Secrets never in git, bundles, presets, argv, or logs — tests assert it.
4. Kenny's real secrets repo is never touched until L8, each step with
   explicit go; development runs against scratch repos.
5. Feature/AR IDs in every commit message.
