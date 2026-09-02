# Pending mini-rounds and open measurements

The visible queue for anything decided but not yet PROVEN. A correction
form's loop (FORM_PROTOCOL §8, field 7) does not close when the measure
is built — it closes when the measurement has actually happened. Keeping
that here rather than in a conversation is the point: a conversation gets
compacted, this file does not.

## Open

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

*(nothing yet — entries move here with the date and the evidence)*
