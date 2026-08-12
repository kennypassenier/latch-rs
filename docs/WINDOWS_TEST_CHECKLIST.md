# Windows 11 — runtime test checklist

latch's logic is verified by the automated suite on Linux, and the code
compiles for the Windows target, but a few things can only be confirmed
by running the real binary on Windows 11 (keyring, paths, the external
git/curl/ssh tools, the two features that degrade by design). Run through
this once after the first Windows release; it takes ~15 minutes.

Prerequisites on the Windows machine: Git for Windows (provides `git`),
the built-in `curl` and OpenSSH client (Windows 10+/11 have both), and the
`latch.exe` for your release. `%USERPROFILE%\.latch` is the home dir.

## 1 · Credentials via the Windows Credential Manager (K4)

- [ ] `latch login --repo <owner/repo>` with a PAT — stored without error.
- [ ] `latch state` shows `keyring : available` (Windows Credential
      Manager), not the file backend.
- [ ] Open *Credential Manager → Windows Credentials* and confirm a
      `latch` entry exists.
- [ ] A second `latch` command does not re-prompt for the PAT.

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
