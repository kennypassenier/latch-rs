# Pending mini-rounds and open measurements

The visible queue for anything decided but not yet PROVEN. A correction
form's loop (FORM_PROTOCOL §8, field 7) does not close when the measure
is built — it closes when the measurement has actually happened. Keeping
that here rather than in a conversation is the point: a conversation gets
compacted, this file does not.

## Open

### M4 · Credentials must survive a reboot without a backup ritual — OPENED 2026-09-26
**What happened, again:** after the reboot of 2026-09-20 `latch state`
on the workstation read `PAT MISSING` and `key MISSING` for all four
projects, with `keyctl show` showing an empty persistent keyring — the
2026-09-02 pattern (kernel keyring, three-day expiry) a second time, and
it surfaced while the dual-boot sync was being set up (the workstation
now boots Garuda and Windows/WSL in turn, so a keyring that forgets is
empty on every other boot by construction).
**Kenny's decision (2026-09-26, dual-boot form, verbatim):** *"het kan
NIET zijn dat ik telkens mijn keys kwijtspeel, en ik wil ook niet meer
afhankelijk zijn van een verplichte backup. Dit proces moet herbekeken
worden. Ik wil op een secure plek in het os mijn credentials één keer
kunnen opslaan en de rest moet gewoon fucking altijd werken."*
**What the code does today** (`crates/core/src/credentials.rs`): reads
env → encrypted file → keyring, but WRITES go to the keyring whenever
one is available and to the file only otherwise. There is no way to
choose the durable store; the durable store is only ever reached by
accident. The escrow gate (D13) protects against loss but is the
"verplichte backup" Kenny no longer accepts as the normal path.
**Mini-round to run in the latch session:** the durable, at-rest
encrypted credential file becomes the primary store (written on every
`login`/`key` operation), the OS keyring at most a cache in front of it
(AR11 session TTL already exists for exactly that role); a config or
`login --store file|keyring` switch is acceptable only if the default is
the durable one. Measure before the form: which of Kenny's machines have
a keyring that outlives a reboot at all (Garuda: no; LXC: no; WSL: to
be measured) — FORM_PROTOCOL §5.6.
**Interim on the workstation (dual-boot build, 2026-09-26):** keys and
PAT are exported once with `latch key show` into an env file inside the
Syncthing-synced `~/.secrets/latch/` (env vars win the chain, K4), so
latch works on both sides today. That is a workaround; this mini-round
is the fix, and closing it removes the env file.
**Proof that closes it:** on the workstation, `latch state` reads every
key as present after a reboot into the OTHER OS with no restore step and
no env override.

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
**Still to tell:** the Homelab Rust project, whose F238 blocks a planned
host-side escrow on this decision. Its session ended before the outcome
existed, so the message never landed — say it there when that project
next opens: the namespace is now per home, so a host that keeps no other
latch credentials can write its own escrow safely.


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
