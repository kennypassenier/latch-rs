# latch v2 — User Guide

Every section is tagged with the feature ID it implements (see
`FEATURES.md`); the same IDs appear in commit messages and tests.

latch keeps `.env` secrets **out of your application repos**: each file is
encrypted with XChaCha20-Poly1305 and stored as ciphertext in one private
GitHub repository. Plaintext exists only in your working tree, in process
memory (`latch run`), or on tmpfs (`latch edit`) — never in git, never in
argv, never in logs.

---

## 1 · First-time setup

### Login (M1)

```
latch login --repo owner/secrets-repo
```

Prompts for a GitHub PAT (or pass `--pat` / set `LATCH_PAT`), **validates
both live** (`git ls-remote`) and stores them via the credential chain
(K4). A wrong PAT or repo name fails immediately, not at first push.

### Link a project (W1)

```
cd ~/code/myapp
latch init                # name defaults to the directory
latch init --name myapp   # explicit
```

Idempotent; refuses to link a subdirectory of an already-linked project.
The project's encryption key is created on first commit.

### Credential storage that works everywhere (K4)

Resolution order for every credential (PAT, project keys, group keys):

1. **Environment variables** — always win. Slot → variable name:
   `key:myapp.prod` → `LATCH_KEY_MYAPP_PROD` (binary slots travel as hex —
   `latch key show --reveal` prints exactly the right form).
2. **Encrypted credential file** — `~/.latch/credentials.enc`, one
   Argon2id-passphrase-encrypted envelope. Used automatically where no OS
   keyring exists (LXC containers, servers). `LATCH_PASSPHRASE` unlocks it
   non-interactively; otherwise you are prompted once per session (AR11
   tmpfs cache, 15 min TTL).
3. **OS keyring** — used automatically on desktops with a Secret Service.

The same commands work in all three worlds; `latch state` (W8) shows which
layer serves what.

---

## 2 · Daily flow

### Commit → push → pull (W2, W3, W4)

```
latch commit              # encrypt env files into the local clone (offline)
latch push                # upload; refuses if the remote moved (S4)
latch pull                # download + decrypt, all-or-nothing
```

- `--env prod` on any of these switches environment (default `dev`).
- Discovery (D1/D8): `.env` and `.env.*` in the project tree; `.env.example`
  and `.env.sample` are templates, not secrets. **`.gitignore` is not
  consulted** — your `.env` belongs there and latch still has to find it.
  Exclusions come from `.latchignore` (gitignore format, negations
  included) plus a built-in list that is always skipped: `.git`, `.latch`,
  `node_modules`, `target`, `vendor`, `.venv`, `venv`. Undo one of those
  with a negation in the project-root `.latchignore`, e.g. `!vendor/`.
  `latch init` leaves a commented starter file behind; commit it.
  The file list is always printed — no surprise pickups.
- Found nothing? `latch commit` says so with a warning instead of a silent
  "0 file(s)", and `latch status --no-ignore` lists the env files the rules
  are hiding (a view only — a commit still respects the rules).
- Commit skips unchanged files (no no-op re-encryptions in history) and
  removes ciphertexts for locally-deleted files.
- **`push` needs a recorded key backup (D13, since 2.3.0).** Publishing is
  the moment your secrets start depending on one key, so latch refuses
  while that key has no escrow on record:

  ```
  ✗ no key backup is recorded for 'myapp' (generation 1) — publishing now
    would put secrets in the repo that only this machine can open
    :: run 'latch key backup <file>' first ...
  ```

  One run of `latch key backup <file>` fixes it for good (safe to re-run,
  and a rotation asks again because the old escrow cannot open what the
  new key seals). `--no-escrow` publishes anyway and records that choice,
  which `latch state` keeps showing until a real escrow covers it. See
  OPERATIONS_RUNBOOK R14 for where an escrow belongs.
- Pull is **all-or-nothing**: one corrupt file means nothing is written.
- Pull refuses to overwrite locally-modified files without `--overwrite`
  (S4); push refuses when the remote has newer work — `latch pull` first,
  or `latch push --force` to make **your** content the newest version.
  Force never rewrites history: your tree is re-committed *on top* of the
  remote head.

### Status and diff (W5, W10)

```
latch status              # clean / modified / local-only / remote-only
latch diff                # key names only
latch diff --reveal       # with values
```

### Run with injected secrets (W6, S5)

```
latch run -- docker compose up
latch run --env prod -- ./deploy.sh
```

Decrypts straight from the clone into the child's environment — nothing
touches disk. Offline? The cached clone serves (S5) with a stale notice.
The child's exit code is latch's exit code.

A process environment is one flat namespace, so `run` merges every env
file of the project into it. Since 2.2.0 (D11) that merge is honest
about collisions: the same variable in two files with the **same** value
merges silently, but **different** values are a hard error naming both
files. Pass `--last-wins` to deliberately keep the alphabetically last
file's value instead.

### Read one file to stdout (D10)

```
latch cat web/.env
latch cat mbtest/mailbox/.env --env prod --expand
```

Decrypts exactly one file to stdout — nothing on disk, no child process.
The path is relative to the project root, whatever your cwd inside the
project. Raw by default (byte-identical to what was committed);
`--expand` resolves `${VAR}` references strictly against the whole
project/environment (and then the D11 collision rules above apply).
Content goes to stdout only; notices and errors go to stderr, so
pipelines can consume the output as-is.

### Templates (W7, AR13)

```
DB_HOST=db.internal
DATABASE_URL=postgres://user:pw@${DB_HOST}:5432/app
```

`${VAR}` references expand **at use time only** (`latch run` and
`latch cat --expand`) — the repo and pulled files keep the raw
references, so round-trips never lose them.
Undefined references and cycles are hard errors naming the variable.

### Edit without touching disk (W11)

```
latch edit                # .env
latch edit .env.local --env prod
```

Committed content → tmpfs file → `$EDITOR` → on save, encrypted straight
into the clone and your working file updated. Refuses to run without a
tmpfs (`XDG_RUNTIME_DIR`) — plaintext never lands on a physical disk. The
temp file is removed on every path, crash included.

### Example files (D3)

```
latch example             # writes .env.example siblings, keys only
```

Only via this explicit command — never a side effect.

---

## 3 · History & integrity

### History and rollback (S3)

```
latch history             # ref | when | message, per project
latch rollback <ref>      # restore in the clone
latch push                # publish the rollback
latch pull --overwrite    # apply it locally
```

Nothing is silent: rollback itself becomes a new commit; old versions stay
in git history forever.

### Verify (S6)

```
latch verify              # audit every ciphertext in the repo
```

Authenticates each envelope with the keys on this machine, without writing
anything: `ok`, `CORRUPT`, `no key (label#generation)`, or `bad format`.
A corrupt file at origin stays reported until a rollback+push heals it —
verify never "heals" by itself.

### State — the doctor (W8)

```
latch state
```

Repo, PAT source, keyring availability, credential file, clone presence,
and per-project key generation + source.

### Reset (W9)

```
latch reset               # wipe clone + session cache; keys and config stay
```

The "start over" button; the next command re-clones.

---

## 4 · File groups (W12)

Share one file's content across projects. First line of a member file:

```
# latch:group=media
```

- Content lives **once** in the repo (`_groups/<env>/<name>.enc`) under
  the group's own key; project entries are pragma-only stubs.
- **Empty member = subscriber**: it receives the group content at the next
  commit and never counts as a change.
- **Exactly one changed member** becomes the new group content; every
  other member — across projects — is rewritten in that same commit.
- **Two changed members = hard error** naming the files and the differing
  keys (W12b). The only way forward is explicit:
  `latch group resolve <name> --source <file>`.
- **Joining** (W12c): empty file + pragma subscribes; identical content
  joins silently; *different* content on a new member errors with both
  remedies — empty the file, or `latch group adopt <name> --from <file>`.
- Groups are global per environment; group keys ride along in K6 backups
  and M2 clones, and inject as e.g. `LATCH_GROUP_MEDIA_DEV`.

```
latch group list          # members, content and key status per group
```

---

## 5 · Keys

### Show (K5)

```
latch key show            # identity, generation, source, env-var name
latch key show --reveal   # + the hex value (exactly what env injection wants)
```

Key material is never printed without `--reveal`.

### Rotate (K3) and per-env keys (K2)

```
latch key rotate              # project key: next generation, re-encrypt
latch key rotate --env prod   # create OR rotate a prod-only key
latch push
```

> ⚠ **The K3 caveat (also printed by the command):** git history keeps the
> old ciphertexts readable with the old key. Full remediation also rotates
> the underlying secret **values**.

`--env` is the entry point for per-environment keys: after it, prod files
decrypt only with the prod key — a machine holding only the dev key cannot
read them (blast-radius isolation). Env keys are never created implicitly.

### Backup & restore (K6)

```
latch key backup ~/latch-keys.bk    # ALL credentials, one encrypted file
latch key restore ~/latch-keys.bk
```

Passphrase-encrypted (prompted twice, or `LATCH_BACKUP_PASSPHRASE`);
covers the PAT, every project/env key and every group key. **Store a copy
offline** — if all machines are lost, the repo is unreadable without it.
Restore also configures the repo on a fresh machine.

---

## 6 · Machines

### Clone credentials to another machine (M2, AR5)

One command over ssh:

```
latch clone --to kenny@server               # whole setup
latch clone --to kenny@server --project myapp
latch clone --to kenny@server --project myapp --env prod
```

Air-gapped / manual (the same machinery):

```
# on the TARGET:   latch clone offer
# on the SOURCE:   latch clone create '<offer>' [--project ..] [--env ..]
# on the TARGET:   latch clone apply '<payload>' --code <6 digits>
```

The payload is sealed (X25519 + XChaCha20) for exactly one offer — safe to
paste anywhere. The **6-digit verify code** binds both machines' public
keys; a mismatch means the payload is not the one your source created and
the apply refuses. Offers are single-use and expire after 15 minutes.
Scoped clones carry exactly their slice — a project's group keys ride
along, other projects' keys never do.

### Project links (D5)

```
latch project list                                  # EVERY project in the repo
latch project bind myapp --dir ~/elsewhere/myapp   # link EXISTING project
latch project unbind myapp                          # forget link; keys stay
latch project remove oldapp                         # retire a project (D9)
```

`bind` refuses unknown names (it never creates) — creation is `latch
init`. `list` is repo-wide: it shows every project in the secrets repo
with its environments and marks which are linked on this machine — the
unlinked ones are your removal candidates.

`remove` deletes ALL of a project's ciphertexts from the repo (a normal
commit+push — history stays) plus the local link. Interactively you must
type the exact project name; headless requires `--yes`. Keys are KEPT by
default so the git history stays readable; `--purge-keys` deletes them
too — after that the history is unreadable forever, so take a `latch key
backup` first. If the removed secrets must truly die, also rotate the
underlying values at their services (the command reminds you).

### Self-update (M5) and path (M4)

```
latch update              # checksum-verified; previous binary kept at latch.prev
latch path                # where latch lives + PATH guidance
```

Update refuses to replace anything unless the download matches the release
manifest **and** the new binary runs `--version` correctly. Any failure
leaves the current install untouched.

### Completions (D7)

```
latch completions bash > ~/.local/share/bash-completion/completions/latch
latch completions zsh   # or fish
```

---

## 7 · The management TUI (G1–G9)

```
latch ui
```

| Screen | What it shows | Keys |
|---|---|---|
| DASHBOARD (G2) | projects, sync state, key presence for the active env | `↑↓` select · `enter` secrets · `c/p/u/d` commit/push/pull/diff |
| KEY MATRIX (G3) | projects × environments: `E`/`F`/`K` source, `*` env-scoped, `✗` missing | `e` cycle env |
| SECRETS (G4) | variables, masked; per-row reveal; add/modify/delete; save = encrypted commit | `r` reveal · `a/m/x` edit · `s` save |
| HISTORY (G6) | versions; rollback behind a confirm | `R` rollback |
| DOCTOR (G8/G9) | W8 state + S6 audit; rotate/backup/restore/login | `v` verify · `R` rotate · `b/B` backup/restore · `l` login |
| CLONE (G7) | guided M2 wizard: target, scope, verify code | `t` target · `→/←` scope · `enter` run |

`tab` switches screens, `e` cycles the environment, `?` help, `q` quits.
All keybinds are letters/arrows — AZERTY-safe. An S4 conflict opens a
choice dialog (pull first / view diff / overwrite deliberately) — the TUI
never forces anything by itself.

---

## 8 · Non-interactive use (M7)

Without a TTY (CI, cron, orchestration) latch **never prompts and never
hangs**: any would-be prompt is a hard error naming the flag or variable
that supplies the answer. Relevant variables:

| Variable | Purpose |
|---|---|
| `LATCH_PAT` | GitHub token (login/validation) |
| `LATCH_PASSPHRASE` | credential-file passphrase |
| `LATCH_BACKUP_PASSPHRASE` | K6 backup/restore |
| `LATCH_KEY_<PROJECT>[_<ENV>]` | project/env key, hex |
| `LATCH_GROUP_<NAME>_<ENV>` | group key, hex |
| `LATCH_HOME` | override `~/.latch` |

Every error message ends with a remedy after `::` (AR6).
