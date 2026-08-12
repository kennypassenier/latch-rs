# latch v2 — Scope

*Reconstructed 2026-08-12 from the conversation record and the built
system (the project predates the formalized procedure); approved via
the retro-fit gate.*

## The problem

Application repos must never contain secrets, but every project needs
its `.env` files on every machine that builds or runs it. v1 (latch,
Python-era design in this repo) proved the idea and failed on
reliability: keyring-only credentials broke on LXCs, a sync stall
could hang forever waiting on hidden input, and blob-corruption bugs
in its bespoke GitHub-API storage eroded trust in the tool that holds
the keys.

## Goal

A ground-up Rust rewrite — "the homelab treatment": every feature
inventoried and rated by Kenny, architecture decided through
adversarial forms, milestone-driven build with tests as first-class
deliverables, full documentation last.

The product: one binary (`latch`) that keeps `.env` secrets encrypted
in a private GitHub repo, works identically on desktop, server and
LXC, never hangs, never loses data silently, and explains every
failure with a remedy.

## Non-goals

- **No team features**: single-admin tool; no sharing model, RBAC,
  or audit trails beyond git history.
- **No custom sync protocol or server**: a private GitHub repo (real
  git) is the only backend.
- **No v1 compatibility**: clean break (AR4); v1 stays beside as
  `latch-legacy`, its repo format is not migrated automatically.
- **No secrets lifecycle management**: latch stores and transports;
  it does not generate, expire or rotate the secret *values*.
- **No non-Linux targets** in v2.0 (release asset is linux-gnu; the
  code avoids gratuitous platform locks but only Linux is tested).

## Success criteria

1. The full daily loop (init → commit → push → pull → run) works on a
   scratch repo from any of the three credential worlds (keyring,
   encrypted file, env injection) — proven by E2E tests against real
   git.
2. Plaintext provably never reaches the repo, argv, logs or backups —
   asserted by tests, not policy.
3. Headless/CI use can never hang: every would-be prompt is a hard
   error naming its answer (M7), swept across the whole CLI surface.
4. A second machine can be stood up from one command (M2 clone) or
   one backup file (K6) — E2E-proven.
5. Every error message carries a remedy in the message itself.
6. Feature-complete against the frozen Phase 2 list (29 Must + 13
   Should), each feature with tests carrying its ID.

## Hard constraints

- Language: Rust (existing repo, Kenny's stack); workspace beside the
  frozen v1 package.
- Storage: private GitHub repository, ciphertext only.
- Tooling: subscription-only (local subagents, /code-review,
  /security-review); no credit-billed extras.
- Development against scratch repos exclusively; Kenny's real secrets
  repo untouched (the planned L8 cutover was retired 2026-08-12:
  nothing uses v1 anymore, v2 starts fresh).
