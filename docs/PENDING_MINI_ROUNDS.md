# Pending mini-rounds and open measurements

The visible queue for anything decided but not yet PROVEN. A correction
form's loop (FORM_PROTOCOL §8, field 7) does not close when the measure
is built — it closes when the measurement has actually happened. Keeping
that here rather than in a conversation is the point: a conversation gets
compacted, this file does not.

## Open

*(empty — every queued measurement and mini-round is closed below, each
with the evidence that closed it. The deferred Windows runtime check is
not a mini-round: it needs Kenny's Win11 machine and lives in
CLAUDE.md.)*

## Closed

### M3 · A scratch `LATCH_HOME` is not scratch for keyring-backed slots — CLOSED 2026-09-02
**Decided:** the keyring namespace follows the latch home (D16). Default
home keeps the service name `latch` so nothing already stored moves; any
other home gets `latch@<resolved home>`, compared on resolved paths so
`LATCH_HOME=~/.latch` still means the ordinary drawer.
**Why this rather than a `--only` flag on backup:** the backup was where
it became visible, not where it went wrong. Under a scratch home
`state`, `key show` and `clone` saw foreign keys too; scoping the
namespace fixes the class, a flag would have fixed one symptom.
**Measured before deciding** (FORM_PROTOCOL §5.6): nothing in Kenny's
`~/Projects` sets `LATCH_HOME` today — the only hits are documentation —
so the change could not orphan a live key anywhere.
**Proven:** `d16_keyring_namespace_tests.rs`. The isolation ran against
the real OS keyring on this machine (two scratch namespaces, never the
machine's own): home A wrote a slot, home B could not read it, cleanup
verified afterwards with `keyctl show`. The test prints "NOT PROVEN
HERE" instead of passing quietly where no keyring exists.
**Told:** the Homelab Rust project, whose F238 blocked a planned
host-side escrow on this decision.


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
