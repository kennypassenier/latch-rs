# latch v2 — Debugging Guide

How to find out what actually happened, and the symptom→cause table for
everything we have seen or designed against.

---

## 1 · The evidence trail

latch keeps its whole world under `~/.latch` (or `LATCH_HOME`):

| Path | What it is | Safe to inspect? |
|---|---|---|
| `config.toml` | repo name, project links, install_dir — plaintext by design | yes |
| `credentials.enc` | salt + AR10 envelope over the slot map | ciphertext only |
| `repo/` | the real git clone of the secrets repo | ciphertext only — full `git log`/`git show` works |
| `groups.json` | W12 local baselines: content fingerprint + member set per group | yes (hashes, no content) |
| `clone-offer.key` | pending M2 offer secret (0600, 15-min TTL) | do not share |
| `update-staging` | M5 download being verified — absent unless an update is mid-flight | yes |
| `$XDG_RUNTIME_DIR/session.key` | AR11 derived-key cache (tmpfs) | gone on reboot |

**The clone is a normal git repository.** `git -C ~/.latch/repo log
--oneline` is the authoritative history; `git show <ref> --stat` shows
which files a version touched. Every file in it must start with the bytes
`LATCH2` — anything else got there outside latch.

Reproduce any command's underlying git operation by hand with
`git -C ~/.latch/repo <verb>`; latch adds nothing hidden (auth travels via
`GIT_CONFIG_*` env, never argv — `ps` shows no token, and neither must
your shell history).

### Verify before you theorize

```
latch state     # which credential comes from where; what is missing
latch verify    # authenticate every ciphertext against your keys
latch status    # local vs committed, per file
```

These three commands answer most "why" questions without guessing.

---

## 2 · Symptom → cause

### Sync

| Symptom | Cause | Fix |
|---|---|---|
| `the remote has newer changes than your base (S4)` on push | someone pushed after your last pull | `latch pull` to take theirs, or `latch push --force` to keep yours (both keep history) |
| `local changes would be overwritten (S4)` on pull | your working file differs from the incoming version | commit+push yours first, or `latch pull --overwrite` |
| pull writes nothing and errors on one file | all-or-nothing rule: one bad envelope aborts the batch | run `latch verify` to name the bad file; fix (rollback+push) and pull again |
| a commit made offline seems to disappear | it did NOT — refresh never resets a dirty clone (found and fixed by the L4 tests) | `latch push` when back online |
| `'X' is not linked to a latch project` | cwd is not under any linked dir | `latch project list`; `latch init` or `latch project bind` |

### Keys & credentials

| Symptom | Cause | Fix |
|---|---|---|
| `…encrypted with key 'X' (generation N) which is not available here` | this machine's key is a different generation (or absent) than what sealed the file | `latch clone` from a machine that has it, or `latch key restore` |
| `no key for project 'X' (env)` | key never arrived on this machine | same as above; check `latch state` |
| `LATCH_KEY_… is not valid hex` | env-injected key pasted wrong | re-copy from `latch key show --reveal` |
| `stored key has N bytes, expected 34` | slot content corrupted or truncated | restore from K6 backup |
| prompted for a passphrase in CI | no TTY answer available — M7 turned the prompt into this error | set `LATCH_PASSPHRASE` (or the named variable) |
| passphrase prompted every command on a desktop | no tmpfs (`XDG_RUNTIME_DIR` unset), so no session cache | run inside a systemd user session, or accept the prompts |
| `backup cannot be opened` | wrong passphrase or file damaged | the file must be byte-identical to what backup wrote |

### Groups (W12)

| Symptom | Cause | Fix |
|---|---|---|
| `group 'X' diverged: … all changed; differing keys: …` | two members edited between commits | `latch group resolve X --source <file>` picks the winner |
| `…subscribes to group 'X' but its content differs` | new member joined with foreign content (W12c) | empty the file (keep pragma) to subscribe, or `latch group adopt X --from <file>` |
| `group 'X' has only empty members and no stored content` | founding commit with nothing to found it on | put the content in ONE member, commit again |
| member file shows only the pragma after pull | the group key is missing here, or content never committed | `latch group list` shows which; clone/inject the group key |
| edit on machine B flagged as a foreign join | pull was skipped, so B has no baseline | pull first — pull registers the baseline; this is by design |

### Integrity & repo

| Symptom | Cause | Fix |
|---|---|---|
| `verify` reports `CORRUPT` on one file | the ciphertext at origin was altered (any byte flip breaks the AEAD) | `latch history` → `latch rollback <good ref>` → `latch push --force` |
| `CORRUPT` persists after reset/re-clone | correct — the origin still holds the bad bytes; verify never heals silently | the rollback above is the heal |
| `bad format` in verify | file in the repo not written by latch (or a future version) | remove it from the repo, or update latch |
| clone in a weird git state | interrupted operation | `latch reset` — wipes only the clone; next command re-clones |
| `another latch process holds the lock` | concurrent latch, or a crash left `lock` behind | stale locks self-break after 15 min; or delete `~/.latch/lock` if you are sure |

### Update (M5)

| Symptom | Cause | Fix |
|---|---|---|
| `checksum mismatch` | download corrupt or tampered | nothing was changed; retry later |
| `the downloaded binary does not run correctly` | broken release asset | nothing was changed; report the release; previous binary keeps working |
| new binary misbehaves after a successful update | — | the previous binary is right there: `mv latch.prev latch` |

### TUI

| Symptom | Cause | Fix |
|---|---|---|
| `latch ui` errors about the terminal | no interactive TTY | use the CLI verbs — every TUI action has one |
| a value shows as `••••••••` | that is the point (G4) | `r` reveals the selected row |

---

## 3 · Digging deeper

- **Reproduce with a scratch repo**: every E2E test in
  `crates/core/tests/` builds a complete two-machine world against a local
  bare repo in a tempdir — copy that pattern to reproduce any scenario
  without touching real secrets.
- **Envelope forensics**: a ciphertext is
  `LATCH2 · version · keyid-len · key-id · generation(LE u16) · 24B nonce
  · body`, with the entire header as AEAD associated data. `xxd file.enc |
  head -2` shows which key/generation sealed it without decrypting
  anything.
- **When filing/fixing a bug**: the standing rule is that every live bug
  becomes a mocked test before the fix (see TEST_PLAN.md) — the mock
  platform in `crates/core/src/platform/mock.rs` can script every effect,
  including subprocess output and the clock.
