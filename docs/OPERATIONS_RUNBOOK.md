# latch v2 — Operations Runbook

Step-by-step procedures for the situations that matter. Every procedure
is safe to abort halfway — latch's writes are atomic and its sync is
explicit.

---

## R1 · Stand up a new machine

**Fast path (from an existing machine):**

```
latch clone --to kenny@newbox
# on newbox:
latch project bind myapp --dir ~/code/myapp
latch pull
```

**From zero (all machines lost):**

```
latch key restore ~/offline/latch-keys.bk   # also configures the repo
latch login                                  # only if the PAT was not in the backup
latch project bind myapp --dir ~/code/myapp
latch pull
```

**Orchestrated (no interaction, e.g. a container):**

```
export LATCH_PASSPHRASE=...            # file-backend passphrase
export LATCH_PAT=ghp_...
export LATCH_KEY_MYAPP=<hex>           # from: latch key show --reveal
latch login --repo owner/secrets
latch init --name myapp
latch pull
```

## R2 · Rotate a compromised key

```
latch key rotate            # or --env prod for one environment
latch push
# every OTHER machine:
latch pull                  # then re-clone the key:
latch clone --to <machine> --project myapp
```

Then rotate the **secret values** themselves (passwords, tokens) — git
history keeps old ciphertexts readable with the old key; the command
prints this caveat for a reason. After values change: edit → commit →
push as usual.

## R3 · Recover from a corrupted repository file

```
latch verify                          # names the corrupt file(s)
latch history                         # pick the last good ref
latch rollback <ref>
latch push --force
latch pull --overwrite                # apply locally
latch verify                          # confirm all-ok
```

## R4 · Undo a bad secrets change

Same as R3 without the corruption: `history → rollback → push → pull`.
The bad version stays in history (nothing is destroyed) — it is simply no
longer the newest.

## R5 · Resolve a group divergence

```
latch group list                                  # see members
latch group resolve <name> --source <file>        # the winner
latch push
# other machines: latch pull
```

The losing edits are overwritten locally on fan-out — if any of that
content matters, copy it out of the file *before* resolving.

## R6 · Take a key backup (do this now)

```
latch key backup ~/latch-keys.bk
```

Copy it somewhere **not on any latch machine** (printed, USB in a drawer,
password-manager attachment). Re-take after every `key rotate`, new
project, or new group. Without a backup and with all machines lost, the
repository is permanently unreadable — by design, and on 2026-09-02 that
stopped being theory.

Since 2.3.0 this is no longer only advice: the backup is also RECORDED,
and `latch push` refuses while a key has no record (D13, see R14).

## R7 · Update latch

```
latch update       # gates: manifest checksum + the new binary must run
latch --version
# regret it?
mv $(latch path | awk 'NR==1{print $3}').prev $(latch path | awk 'NR==1{print $3}')
```

## R8 · Move the secrets repository

1. Create the new private repo on GitHub.
2. Mirror: `git -C ~/.latch/repo push --mirror https://github.com/owner/new-repo.git`
3. `latch login --repo owner/new-repo` (re-validates), on every machine.
4. `latch reset && latch status` — re-clones from the new origin.

## R9 · Decommission a machine

```
latch reset                      # clone + session cache gone
rm -rf ~/.latch                  # config + credential file gone
```

Keyring entries (desktops): remove the `latch` service entries via your
keyring manager. Then rotate any keys that machine held (R2) if the
machine is leaving your control.

## R10 · CI / orchestration checklist (M7)

- Inject exactly what the job needs: `LATCH_KEY_<PROJECT>[_<ENV>]` (+
  `LATCH_GROUP_…` for groups), nothing more — scoped blast radius.
- `latch run --env <env> -- <cmd>` is the whole integration; no files.
- Everything prompts-as-errors: a hang is impossible, a missing credential
  is a named error with the variable to set.
- The PAT is only needed where the job must reach the repo (pull/push);
  `run` works from the cached clone without network (S5) — but the cache
  must have been pulled at least once.

## R12 · Retire a project you no longer use

```
latch project list            # repo-wide: unlinked entries are candidates
latch project remove <name>   # type the name to confirm
```

Keys are kept, so the git history stays readable if you ever need an old
value back. Only when you are sure nothing in that history matters:
`latch key backup` first, then `latch project remove <name> --purge-keys`.
If the removed secrets are live anywhere (API keys, passwords), rotate
those VALUES at their services — history keeps the old ciphertexts.

## R13 · Enable the commit gates in a clone (maintainer, once per clone)

Do this before the first commit in any fresh clone of this repository:

```
git config core.hooksPath .githooks     # or: make install-hooks
git config --get core.hooksPath         # must print: .githooks
```

Why it needs saying out loud: `core.hooksPath` is **local** git config.
It is not committed and a clone does not inherit it, so a clone without
this command has no enforcement whatsoever — and nothing announces that.
latch itself sat in exactly that state until 2026-08-30: `.githooks/`
existed, `core.hooksPath` was never set, and every commit made from
outside a Claude session in this directory passed unchecked.

What the two hooks do once enabled:

- `.githooks/pre-commit` runs `.claude/hooks/gates.sh` — `cargo fmt
  --check`, `cargo clippy --all-targets -D warnings`, the full test
  suite over `latch-core`/`latch-cli`/`latch-ui`, plus the check that
  the tree did not change while the gates ran. The frozen legacy
  package is deliberately ungated (AR14).
- `.githooks/commit-msg` refuses a message without feature IDs in
  brackets (`[W12, AR9]`; `[meta]` for pure infrastructure).

Both fire for every commit from any session, terminal or tool. The
Claude Code hook in `.claude/settings.json` runs the same two gates but
only for sessions opened in this directory; it stays as a second layer.

Bypassing (`git commit --no-verify`) is not part of any procedure here.

## R14 · Key escrow: the second copy latch insists on (D13)

Since 2.3.0 latch refuses to publish secrets sealed with a key that has
no recorded backup. One command satisfies it, and it is safe to re-run:

```
latch key backup ~/latch-keys-<date>.latchbk
latch state          # escrow: recorded for gen 1 — <path> (file still there)
```

What the record is: a note in the secrets repo at
`_escrow/<key label>.json` — label, generation, timestamp, and the sha256
of the escrow file. No key material, no passphrase. It lives in the repo
because the repo is what survives losing this machine.

What it is NOT: proof that your escrow file still exists. latch re-checks
the fingerprint when the file is still at its recorded path and says so
plainly; once you move the escrow off this machine — which you should —
it reports "not at that path on this machine, which is fine if you moved
it off". A guarantee latch cannot keep would be worse than an honest
report.

Rules worth knowing:
- **A rotation needs a new escrow.** `latch key rotate` mints a new
  generation and the old escrow cannot open what the new key seals, so
  the next push asks again.
- **`--no-escrow` exists and is recorded.** It publishes without an
  escrow and leaves a line in `latch state` that stays until a real
  escrow covers that generation. Use it for a throwaway, not as habit.
- **Where the escrow belongs:** somewhere that is not this machine. The
  homelab's now sits in three places of different kinds (workstation,
  the Proxmox host's vault, and restic offsite). Three copies of one
  passphrase-encrypted file is cheap; the alternative was losing
  everything to a package upgrade.

## R15 · Recover after losing every key (what 2026-09-02 taught)

**Step 0, before anything else: check whether the keys are actually
gone.** On Linux they live in the kernel keyring, and a fresh login
session does not attach the persistent one by itself:

```
keyctl get_persistent @s        # attach it
keyctl show                     # expect: user: keyring-rs:key:<project>@latch
latch state                     # keys reappear if they were only detached
```

This costs ten seconds and it is the difference between "not linked" and
"lost". On 2026-09-02 two of four projects were re-minted before anyone
looked here, and re-minting threw away their history for nothing.

If the credential store is genuinely wiped and no escrow exists, the
ciphertexts in the repo cannot be opened by anyone, and re-minting is the
only path.
Full recipe, written from the homelab's successful recovery:
`~/Projects/homelab/docs/deployment/HANDOVER_LATCH_RECOVERY.md`. The
short version, in order:

1. `latch login` (Kenny enters the PAT).
2. Back up the ciphertext first: `cp -a ~/.latch/repo ~/.latch/repo.backup-<date>` — re-minting is one-way.
3. `git check-ignore -v <path>/.env` before writing any plaintext into a working tree.
4. Collect the plaintext from wherever it still runs (host vault, `EnvironmentFile`, a running container).
5. `latch commit --env <env>` — it publishes only what is on disk, so check the removal list.
6. Verify with `latch cat <file> --env <env>` BEFORE pushing.
7. `latch push`, then shred the plaintext from the working tree.
8. `latch key backup <file>` — which since 2.3.0 also records the escrow, and without which the push in step 7 refuses.

What you lose by re-minting: the values survive, the history does not.
`latch history` and `latch rollback` restart at generation 1.

## R11 · Release a new latch version (maintainer)

### One-time signing setup (do this ONCE, before the first release)

The self-updater (D4/AR20) trusts a release only if `SHA256SUMS` carries a
valid minisign signature under a key baked into the binary. Generate the
keypair once and keep the secret key OFFLINE (never on GitHub):

```bash
sudo pacman -S minisign            # Garuda
minisign -G                        # → ~/.minisign/minisign.key + .pub
```

On Windows the tool is identical (`winget install jedisct1.minisign`,
then `minisign -G`); or copy the same `minisign.key` across so both
machines share one key.

Then bake the PUBLIC key into the source and rebuild:
- open `crates/core/src/ops/update.rs`
- replace `RELEASE_PUBKEY` with the second line of `minisign.pub` (the
  base64 blob, without the comment line)
- commit `[meta]`, and cut releases from this build onward.

Until a real key is set, `latch update` fails closed (refuses every
release) — safe, but nobody can self-update, so do this before relying on
updates.

### Per release

```bash
git tag v2.x.y && git push --tags        # CI builds Linux + Windows + SHA256SUMS
# wait for the release workflow to finish, then sign locally:
scripts/sign-release.sh v2.x.y           # Garuda  (or scripts\sign-release.ps1 on Windows)
```

CI builds both OS binaries and one `SHA256SUMS`, publishes the Release,
but does NOT sign (the secret key never touches GitHub). The sign script
downloads the manifest, signs it with your offline key, and uploads
`SHA256SUMS.minisig`. Verify afterwards from a previous build on each OS:
`latch update` must find, verify the signature, and install; a release
without a valid `.minisig` must be refused.
