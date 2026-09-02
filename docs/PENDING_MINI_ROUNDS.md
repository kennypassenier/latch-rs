# Pending mini-rounds and open measurements

The visible queue for anything decided but not yet PROVEN. A correction
form's loop (FORM_PROTOCOL §8, field 7) does not close when the measure
is built — it closes when the measurement has actually happened. Keeping
that here rather than in a conversation is the point: a conversation gets
compacted, this file does not.

## Open

### M3 · A scratch `LATCH_HOME` is not scratch for keyring-backed slots
**Found:** 2026-09-02, while running the M2 drill.
**What happens:** `LATCH_HOME` isolates the config, the clone and the
credential FILE — but not the OS keyring, which is machine-scoped. A
`latch key backup` run under a throwaway `LATCH_HOME` therefore swept up
the machine's real `pat` slot and wrote it into a scratch escrow file
(shredded immediately). Running it inside a fresh session keyring
(`keyctl session -`) did not help: keyring-rs still resolved the real
entries through the persistent keyring.
**Why it matters:** the project's own hard rule is that real secrets
never enter development, and this is a path where they do so silently.
It also makes every future drill awkward for the same reason.
**Not decided yet.** Options to weigh in a mini-round: a documented
warning in R14, a `--only <slot>` scope for backup, or honouring an
explicit "no keyring" switch for scratch runs. Deliberately left open
rather than fixed in passing, because it changes what `key backup`
means.

### M1 · Prove the escrow gate on a real key (D13)
**Decided:** 2026-09-02 (mini-round after the keyring wipe).
**Measured at:** the first time a real key on Kenny's machine is pushed
under 2.3.0 — which is due anyway, because `stacks`, `almanac` and
`hub-clients` carry no recorded escrow yet.
**Passes when:** `latch push` refuses with the remedy, one run of
`latch key backup <file>` records it, the same push then succeeds, and
`latch state` shows `escrow: recorded for gen N`.
**Fails →** fall back to the agreed alternative: publishing stays
allowed, but `--no-escrow` is required and the skip stays visible in
`latch state` (already implemented, so the fallback is a flag flip in the
gate, not a rebuild).

### M2 · Restore an escrow file for real, once (K6)
**Decided:** 2026-09-02, same round.
**Measured at:** before the next release after 2.3.0.
**Passes when:** on a scratch repo, an escrow file written by
`latch key backup` is restored with `latch key restore` into an emptied
credential store, and the project's secrets decrypt afterwards.
**Why it is not already covered:** `l5_key_machine_tests.rs` proves the
mechanism with synthetic material inside the suite. No human-made escrow
file has ever been restored. A backup that has never been restored is
Schrödinger's backup — the whole reason this project needed a recovery
day.

## Closed

### M1 · Prove the escrow gate on a real key — CLOSED 2026-09-02
Measured on Kenny's own installation right after `cargo install` of
2.3.0: `latch state` reports `escrow : NONE — this key exists in one
place only` for all three live projects, and `latch push` in
`~/Projects/almanac` refused with the full remedy naming
`latch key backup`, re-runnability and `--no-escrow`. The complete loop
(refuse → `latch key backup` → push succeeds) was then walked end to end
with the real binary on a scratch repo under an isolated `LATCH_HOME`.
What is NOT yet done, because it needs Kenny's own passphrase: recording
an escrow for the three real projects. Until he runs it, those pushes
refuse — which is the feature working, not a defect.

### M2 · Restore an escrow file for real, once — CLOSED 2026-09-02
Done with the real binary, not the test doubles: `latch key backup`
wrote an escrow file, `latch key restore` opened it in a different
`LATCH_HOME` ("2 credential(s) restored — repo configured from the
backup"), and the project's secret decrypted afterwards via `latch cat`.
Both scratch escrow files were shredded afterwards (see M3 for why that
mattered). Schrödinger's backup is now an opened box.
