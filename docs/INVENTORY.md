# latch v1 — Feature inventory (Phase 1, brownfield)

*Reconstructed 2026-08-12. During the actual redesign this inventory
was folded directly into the Phase 2 rating forms; this document
restores it as a standalone artifact. Source of truth for behaviour:
the frozen v1 package (`src/`, binary `latch-legacy`) and the archived
v1 docs in `docs/legacy/`.*

Each entry names the Phase 2 feature ID it became. Verdicts are the
frozen Phase 2 outcomes; v1 defects noted here drove the redesign.

## What v1 had

| v1 capability | Became | Phase 2 verdict | v1 state / defect driving the redesign |
|---|---|---|---|
| XChaCha20-Poly1305 encryption of `.env` files | K1 | Must | worked; header not authenticated as AAD |
| Per-project keys, per-env variant | K1/K2 | Must / Should | worked |
| Key rotation | K3 | Must | existed; history caveat undocumented |
| OS-keyring credential storage | K4 | Must (redesigned) | **keyring-only — failed on Kenny's LXCs**; replaced by env → encrypted file → keyring chain |
| Key show/export | K5 | Should | existed |
| Private GitHub repo as backend, via bespoke GitHub blob API | S1/AR2 | Must (rebuilt) | **blob-corruption bugs (binary content by-sha path)**; replaced by a real local git clone |
| Manifest / repo index | S2 | Must | existed; superseded by AR9 self-describing layout |
| History + rollback via commit history | S3 | Must | existed |
| Overwrite protection | S4 | Must | partial; now git's own non-fast-forward |
| `latch init/commit/push/pull/status` | W1-W5 | Must | worked; sync could **stall forever on hidden prompts** (the M7 origin story) |
| `latch run` with env injection | W6 | Must | worked |
| `${VAR}` template expansion | W7 | Should | existed; expansion timing unspecified — now strictly at use time (AR13) |
| Doctor/state command | W8 | Should (reborn) | rudimentary |
| Reset | W9 | Should | existed |
| Automatic `.env` discovery, path flattening | D1/D2 | Must | existed; flattening not provably bijective |
| `.env.example` generation | D3 | Must | **ran implicitly**; now behind an explicit command per Kenny |
| Global + project config | D4 | Must | existed |
| Project bind/unbind | D5 | Should | existed |
| CLI with confirmations/progress | D6 | Must | existed; error messages without remedies |
| `latch login` | M1 | Must (now validating) | stored without validating — failures surfaced at first push |
| Machine clone (X25519 offer/payload) | M2 | Must (redesigned) | machinery worked; multi-command UX → one scoped command (AR5) |
| "Clone groups" | M3 → W12 | withdrawn / re-rated | mischaracterized in the first inventory pass — actually the pragma-based **file content groups**, redesigned in full as W12a-d |
| `latch path` | M4 | Should | existed |
| Self-update | M5 | Must (homelab-grade) | existed; no checksum manifest, no keep-previous, no verify-before-replace |
| APT repository idea | M6 | Won't | never built |
| Pragma-linked file groups (`# latch:group=`) | W12 | Should (design approved) | existed with reliability issues ("temporarily disabled" in the v1 README); redesigned around a local baseline + explicit divergence resolution |

## What v1 did not have (added in the Phase 2 proposal round)

K6 key backup/restore · M7 non-interactive contract · S5 offline
cache semantics · S6 repo-wide verify · W10 masked diff · W11 tmpfs
edit · D7 completions · S7 second backend (rejected) · the whole
G-series management TUI (Kenny's proposal).

## Open defects at freeze time (all structurally addressed in v2)

1. Credential sync stall — waiting on hidden input with no TTY (→ M7
   hard-error contract, swept surface-wide).
2. GitHub blob corruption on binary content (→ AR2 real git clone).
3. Keyring-only storage failing headless (→ K4 chain).
4. Groups divergence with silent last-writer-wins risk (→ W12b hard
   error + explicit resolve).
