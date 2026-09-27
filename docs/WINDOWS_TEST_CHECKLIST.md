# Windows 11 — runtime test checklist

latch's logic is verified by the automated suite on Linux, and the code
compiles for the Windows target, but a few things can only be confirmed
by running the real binary on Windows 11 (keyring, paths, the external
git/curl/ssh tools, the two features that degrade by design). Run through
this once after the first Windows release; it takes ~15 minutes.

Prerequisites on the Windows machine: Git for Windows (provides `git`),
the built-in `curl` and OpenSSH client (Windows 10+/11 have both), and the
`latch.exe` for your release. `%USERPROFILE%\.latch` is the home dir.

## 1 · Credentials in the durable file (K4, M4)

Since 2.5.0 every write goes to the encrypted credential file on every OS,
Windows included; the Credential Manager is only read, for values an
older latch stored there (fix-win-keyring-1 made that read real).

- [ ] `latch login --repo <owner/repo>` with a PAT — "token stored in the
      encrypted credential file".
- [ ] `latch state` in a second process shows `PAT : present (File)` and
      `cred file : present`; `%USERPROFILE%\.latch` holds
      `credentials.enc` and `credentials.key`.
- [ ] A second `latch` command does not prompt for the PAT or a
      passphrase.

## 2 · The daily loop against real git (W1–W6)

- [ ] In a project dir: `latch init`, add a `.env`, `latch commit`,
      `latch push` — all succeed (watch for path-separator issues; repo
      paths use `/` which git accepts on Windows).
- [ ] In a fresh dir: `latch project bind <name>` then `latch pull` —
      the `.env` reappears with identical bytes.
- [ ] `latch run -- cmd /c "echo %SOME_KEY%"` prints the injected value
      (no file on disk).
- [ ] `latch status` / `latch diff` read correctly.

## 3 · The two by-design degradations

- [ ] `latch edit` refuses with the Windows message ("needs a RAM-backed
      filesystem, which Windows lacks — edit the file with your editor and
      run 'latch commit'"). This is WA, expected.
- [ ] Using the file backend would prompt for the passphrase each time
      (WB, no session cache) — but note you normally won't hit the file
      backend because the Credential Manager is present.

## 4 · Machine clone (M2)

- [ ] `latch clone --to <user@linux-host>` from Windows completes (needs
      the OpenSSH client on PATH and `latch` on the remote).
- [ ] The manual path (`latch clone offer` on Windows, `create` on the
      source, `apply` on Windows) works and the verify code matches.

## 5 · Self-update (M5 + D4), AFTER a signed release exists

- [ ] `latch update` on an older Windows build finds the release,
      downloads `latch-x86_64-pc-windows-msvc.exe`, verifies the minisign
      signature, and installs — `latch --version` shows the new version.
- [ ] `latch.exe.prev` exists next to the binary (the kept previous).
- [ ] Tamper test (optional): point `latch update` at a release whose
      `SHA256SUMS.minisig` is missing/edited → it refuses, nothing
      changes.

## 6 · Privacy of the home directory

- [ ] `%USERPROFILE%\.latch` is not readable by other user accounts
      (default NTFS ACLs on the profile dir; latch relies on this rather
      than a Unix mode).

Record anything that fails here as a bug → it becomes a test before the
fix (standing rule 8). Path handling and the external-tool calls are the
most likely to surprise.

## Run log

### 2026-09-26 — partial run, Windows 11 (NT 10.0.26200), latch 2.4.0
Driven from WSL through interop against `latch-x86_64-pc-windows-msvc.exe`
from the v2.4.0 release (SHA256 and minisign signature verified), with a
scratch `LATCH_HOME` under `%TEMP%\latch-wincheck`.
- §1 partly: `latch state` → `keyring : available`. Login blocked: Git for
  Windows is not installed on this machine, and latch refuses cleanly with
  `spawn git: program not found :: is 'git' installed and on PATH?`.
- §2, §4, §5: not run — all need `git` on PATH.
- §3: `latch edit` outside a project refuses before reaching the WA
  message; the WA text itself still needs a bound project.
- §6: passed. `%USERPROFILE%` ACL grants only SYSTEM, Administrators and
  the user (plus an AppContainer SID with execute-only).
- Found: `error:`/`warning:` labels printed raw ANSI escapes into a
  redirected stderr → fix-color-1 (test first, then fix).

### 2026-09-26 — full run, Windows 11 (NT 10.0.26200), latch 2.5.0
Release binary from the v2.5.0 tag (SHA256 verified; not yet signed),
Git for Windows 2.55.0 installed with winget, scratch `LATCH_HOME` under
`%TEMP%\latch-wincheck`, scratch project `wincheck` in
`kennypassenier/secrets`.
- §1 passed: login stored the PAT in the file; a second process read
  `PAT : present (File)` without any prompt.
- §2 passed with `latch init --name wincheck`: commit, push
  (`--no-escrow`), bind + pull in a fresh directory gave identical bytes,
  `latch run -- cmd /c "echo %SOME_KEY%"` printed the value, status and
  diff read correctly. Found: the default project name took the whole
  path, and a `sub\.env` was never discovered → fix-win-paths-1.
- §3 passed: `latch edit` refuses with the WA message.
- §4 manual path passed (offer → create `--project wincheck` → apply
  `--code`), between two scratch homes on this machine. `clone --to` not
  run: no ssh target with latch is set up from Windows.
- §5 open: needs a signed release newer than the installed build.
- §6 passed earlier the same day.
- Found: `latch path` suggested `export PATH=".:$PATH"` → fix-win-paths-1.

### 2026-09-27 — §5 and the path recheck, latch 2.5.1 / 2.5.2
- Path recheck with the signed 2.5.1 passed: default project name
  `nested-app`, `sub/.env` listed, PowerShell remedy from `latch path`.
- §5 found fix-win-update-1: 2.4.0 → 2.5.1 failed with "Access is
  denied". Fixed in 2.5.2. The updater that runs is the OLD binary, so
  a Windows build before 2.5.2 still cannot update itself: replace it by
  hand once (download `latch-x86_64-pc-windows-msvc.exe`).
- §5 passed with the signed 2.5.2: `latch update --reinstall` fetched,
  verified the minisign signature and replaced the running exe; the
  previous binary sat at `latch.exe.prev`, the moved-aside one at
  `latch.exe.old` (cleared at the next update). Tamper test not run.
