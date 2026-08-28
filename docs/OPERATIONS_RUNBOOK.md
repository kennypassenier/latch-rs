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
repository is permanently unreadable — by design.

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
