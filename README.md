# Latch

Encrypted `.env` secrets management backed by a private GitHub repository.

Latch keeps your team's secrets out of application repositories by encrypting every `.env` file with a per-project (or per-environment) XChaCha20-Poly1305 key and storing the ciphertext in a dedicated secrets repository on GitHub. Team members pull and decrypt locally; CI/CD pipelines inject secrets directly into subprocesses without ever touching the filesystem.

---

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [First-time global setup](#first-time-global-setup)
- [Per-project setup](#per-project-setup)
- [Commands](#commands)
  - [latch init](#latch-init)
  - [latch save](#latch-save)
  - [latch export](#latch-export)
  - [latch status](#latch-status)
  - [latch rotate](#latch-rotate)
  - [latch run](#latch-run)
  - [latch key](#latch-key)
  - [latch path](#latch-path)
- [Credential resolution](#credential-resolution)
- [Environment variables](#environment-variables)
- [Configuration files](#configuration-files)
- [Use cases](#use-cases)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust 1.86+ | `rustup update stable` |
| A private GitHub repository | Used exclusively to store encrypted secrets. Never put source code here. |
| A GitHub Personal Access Token (PAT) | Needs `Contents: read/write` permission on the secrets repository. [Create one here](https://github.com/settings/tokens). |
| OS keyring | macOS Keychain, GNOME Keyring / KWallet on Linux, Windows Credential Manager. Optional but recommended. |

---

## Installation

### Build from source

```bash
git clone https://github.com/your-org/latch-rs
cd latch-rs
cargo install --path .
```

### Verify

```bash
latch --help
```

---

## First-time global setup

Latch stores global configuration at `~/.latch/config.toml`. The file is created automatically the first time you run `latch init`. You do not need to edit it manually.

Create your secrets repository on GitHub first. It should be **private** and contain only Latch-managed ciphertext. A good naming convention is `your-org/secrets` or `your-org/env-vault`.

---

## Per-project setup

Run the following from the root of your application repository:

```bash
cd ~/code/my-app
latch init
```

Latch will ask you for:

1. **Project name** — a short identifier used as the remote path prefix (e.g. `my-app`).
2. **Secrets repository** — owner/repo on GitHub (e.g. `acme-corp/secrets`).
3. **GitHub PAT** — stored in the OS keyring under `latch / my-app.pat`.
4. **Default environment** — usually `dev`.
5. **Encryption key** — you can generate a random key, derive one from a passphrase using Argon2id, or paste an existing key. The key is stored in the OS keyring under `latch / my-app.key`.

After `latch init`, two files are written into your project:

- `.latch/config.toml` — project metadata (commit this).
- `.latchignore` — optional exclude patterns (commit this).

The manifest (`my-app/manifest.json`) is pushed to your secrets repository and tracks every file Latch manages.

### What to commit

```
.latch/config.toml   ✓ commit
.latchignore         ✓ commit
.env                 ✗ never commit  (add to .gitignore)
.env.example         ✓ commit  (generated automatically by latch save)
```

---

## Commands

### latch init

Interactive project initialisation. Run once per project.

```
latch init
```

Creates `.latch/config.toml`, saves credentials to the OS keyring, and pushes the initial manifest to the secrets repository.

---

### latch save

Encrypt local `.env` files and push them to the secrets repository.

```
latch save [--env <env>]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment label used as the remote path prefix. |

**What it does:**
1. Walks the project tree using `.latchignore` rules. `.gitignore` does not suppress `.env` discovery.
2. Encrypts each discovered `.env` file with XChaCha20-Poly1305.
3. Pushes each ciphertext to `<project>/<env>/<flat-name>.enc` in the secrets repository.
4. Generates a `.env.example` next to each `.env` file (values stripped, keys and comments kept).
5. Removes stale remote encrypted files that were previously tracked for the env but are no longer discovered.
6. Updates the remote manifest.

**Example:**

```bash
# Save dev secrets
latch save

# Save production secrets (uses prod key if one is set)
latch save --env prod
```

---

### latch export

Pull ciphertext from the secrets repository and decrypt it to local `.env` files.

```
latch export [--env <env>] [--dry-run]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment to pull from. |
| `--dry-run` | off | Print what would be written without touching the filesystem. |

If a local `.env` file already exists and its content differs from the remote, Latch shows an inline diff and asks for confirmation before overwriting.

**Example:**

```bash
# Pull dev secrets
latch export

# Preview what prod export would do (no writes)
latch export --env prod --dry-run

# Pull staging secrets
latch export --env staging
```

---

### latch status

Compare local `.env` files against the current remote state.

```
latch status [--env <env>]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment to compare against. |

Output uses simple icons:

| Icon | Meaning |
|---|---|
| `✓` | In sync — local matches remote. |
| `~` | Modified — local differs from remote. Run `latch save` to push changes. |
| `!` | Missing locally — remote has this file but it does not exist locally. Run `latch export` to pull it. |
| `✗` | Error fetching or decrypting. |

**Example:**

```bash
latch status
latch status --env staging
```

---

### latch rotate

Re-encrypt all secrets with a new key.

```
latch rotate
```

Latch will:
1. Load the current key from the credential chain.
2. Download and decrypt every file in the manifest.
3. Prompt you to choose a new key (generate, derive from passphrase, or paste).
4. Re-encrypt every file with the new key and push.
5. Save the new key to the OS keyring.
6. Print the new key so you can distribute it to teammates.

**After rotating** you must share the new key with every team member (via a secure channel) and update the key in all CI/CD environments.

---

### latch run

Run a subprocess with decrypted secrets injected into its environment. Secrets never touch the filesystem.

```
latch run [--env <env>] -- <program> [args…]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment whose secrets to inject. |

Template references (`${VAR}` and `$VAR`) within values are expanded before injection (feature 8.4). Variables defined earlier in the same `.env` file can be referenced by later lines.

The exit code of the subprocess is propagated.

**Examples:**

```bash
# Start a dev server with dev secrets
latch run -- node server.js

# Run a database migration against staging
latch run --env staging -- npm run migrate

# Execute a Python script with prod secrets
latch run --env prod -- python manage.py collectstatic

# Template expansion: if DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/mydb
# then DB_HOST and DB_PORT are expanded before injection
latch run --env prod -- ./check-db.sh
```

---

### latch key

Set or rotate the encryption key for a specific environment (multi-key support, feature 8.5).

```
latch key [--env <env>]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | (none) | Environment to set a key for. Omit to update the default project-wide key. |

When `--env` is provided, the key is stored in the OS keyring under the slot `<project>.key.<env>`. Commands that take `--env` will automatically prefer this env-specific key over the project-wide default.

**Examples:**

```bash
# Set a dedicated prod key (recommended — keeps dev and prod access separate)
latch key --env prod

# Update the default key for all environments that don't have their own
latch key

# Set a staging-specific key
latch key --env staging
```

After setting env-specific keys, `latch save --env prod` encrypts with the prod key, and only someone with that key can run `latch export --env prod`.

---

### latch path

Install or remove the current Latch binary from your user PATH.

```
latch path <add|remove|status>
```

| Command | Description |
|---|---|
| `latch path add` | Copies the current binary into a user-level install directory and configures PATH. |
| `latch path remove` | Removes the managed install and undoes the PATH integration block. |
| `latch path status` | Shows the current binary path, install location, and PATH status. |

**Platform behavior:**
1. Linux/macOS installs to `~/.local/bin/latch` and manages a small PATH block in shell profile files.
2. Windows installs to `%LOCALAPPDATA%\Programs\latch\latch.exe` and updates the user PATH.

**Examples:**

```bash
# Install the current binary so `latch` works without `./`
./latch path add

# Check whether PATH is configured correctly
latch path status

# Remove the user-level PATH installation
latch path remove
```

---

## Credential resolution

For each project, Latch looks for the encryption key and GitHub PAT in this order:

1. **OS keyring** (env-specific slot) — `<project>.key.<env>` *(key only, when `--env` is supplied)*
2. **OS keyring** (project-wide slot) — `<project>.key` / `<project>.pat`
3. **Environment variables** — `LATCH_KEY` / `LATCH_PAT`
4. **`~/.latch/config.toml`** — `key_hex` / `github_pat` fields

The first non-empty value wins.

---

## Environment variables

| Variable | Description |
|---|---|
| `LATCH_KEY` | Hex-encoded (64 chars) or base64-encoded (44 chars) 32-byte encryption key. |
| `LATCH_PAT` | GitHub Personal Access Token. |
| `RUST_LOG` | Control log verbosity. E.g. `RUST_LOG=debug latch save`. |

These are especially useful in CI/CD where an OS keyring is unavailable.

---

## Configuration files

### `~/.latch/config.toml` (global)

Created automatically. Stores a list of known projects.

```toml
[[projects]]
name = "my-app"
secrets_repo = "acme-corp/secrets"
default_env = "dev"
# key_hex and github_pat are optional fallbacks if the keyring is unavailable
```

### `.latch/config.toml` (per-project)

Committed to your application repository.

```toml
name = "my-app"
secrets_repo = "acme-corp/secrets"
default_env = "dev"
```

### `.latchignore`

Glob patterns to exclude from scanning. Same syntax as `.gitignore`.

```
# Don't track test fixtures
tests/fixtures/
# Don't track example files
*.example
```

---

## Use cases

### Onboarding a new team member

```bash
# Clone the app repo
git clone git@github.com:acme-corp/my-app
cd my-app

# Install latch
cargo install --path path/to/latch-rs

# Initialise — paste the shared PAT and the dev key when prompted
latch init

# Pull dev secrets
latch export
```

### CI/CD (GitHub Actions example)

```yaml
- name: Export secrets
  env:
    LATCH_KEY: ${{ secrets.LATCH_KEY_PROD }}
    LATCH_PAT: ${{ secrets.LATCH_PAT }}
  run: latch export --env prod
```

Or — to avoid writing secrets to disk entirely:

```yaml
- name: Run tests with secrets injected
  env:
    LATCH_KEY: ${{ secrets.LATCH_KEY_DEV }}
    LATCH_PAT: ${{ secrets.LATCH_PAT }}
  run: latch run --env dev -- cargo test
```

### Keep `.env` ignored by Git but still tracked by Latch

```gitignore
# Git should ignore secrets
.env
.env.*
```

```text
# .latchignore controls Latch scanning (not .gitignore)
# You can still explicitly exclude paths from Latch here.
tests/fixtures/
```

`latch save` will still discover and encrypt `.env` files even when they are gitignored.

### Stop tracking a previously encrypted file

If you add a path to `.latchignore`, then run:

```bash
latch save --env dev
```

Latch removes that file's ciphertext from the remote repo for `dev` and prunes it from `manifest.json`.

### Monorepo with multiple services

Each service calls `latch init` with its own project name:

```
my-monorepo/
  services/
    api/          → project name "monorepo-api"
    worker/       → project name "monorepo-worker"
    frontend/     → project name "monorepo-frontend"
```

Secrets are stored at separate prefixes inside the same secrets repository:

```
acme-corp/secrets
  monorepo-api/dev/backend.env.enc
  monorepo-worker/dev/worker.env.enc
  monorepo-frontend/dev/frontend.env.enc
```

### Strict prod access control (multi-key)

```bash
# After init (dev key is already set), add a separate prod key
latch key --env prod
# → prompts for a new key; stores it as "my-app.key.prod" in keyring

# Save prod secrets — encrypted with the prod key only
latch save --env prod

# Only engineers with the prod key can export prod secrets
latch export --env prod
```

Developers with only the dev key cannot decrypt prod secrets even if they have access to the secrets repository.

### Template variable expansion

```dotenv
# .env
DB_HOST=db.internal
DB_PORT=5432
DB_NAME=myapp
DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/${DB_NAME}
```

When running `latch run`, `DATABASE_URL` is injected as `postgres://db.internal:5432/myapp` into the subprocess without modifying the stored `.env` file.

---

## Security model

- **Encryption:** XChaCha20-Poly1305 with a fresh random 24-byte nonce per file per write. Provides authenticated encryption — any tampering causes decryption to fail.
- **Key derivation:** When you choose the passphrase option, Argon2id (m=64 MiB, t=3, p=4) derives the key. The random salt is stored alongside the ciphertext in the manifest so it can be shared safely.
- **Key storage:** Keys are stored in the OS native keyring (macOS Keychain, Windows Credential Manager, GNOME Keyring / KWallet). They are never written to `.latch/config.toml` unless you explicitly set `key_hex` as a fallback.
- **No plaintext on remote:** The secrets repository contains only opaque ciphertext blobs and the manifest JSON (which contains only file names, not values).
- **No plaintext on disk (latch run):** `latch run` decrypts into process memory only. Files are not written.
- **Conflict detection:** The GitHub client fetches the current blob SHA before every push. Concurrent writes to the same file are rejected by the GitHub API.
- **OWASP considerations:** Latch uses HTTPS for all GitHub API calls, never logs plaintext secrets, and clears sensitive strings from memory where possible.

---

## Troubleshooting

### `No encryption key found for project 'my-app'`

Run `latch init` in the project root, or set `LATCH_KEY` in the environment.

### `manifest.json not found`

The project has not been initialised against this secrets repository. Run `latch init`.

### Keyring not available (e.g. headless Linux CI)

Set `LATCH_KEY` and `LATCH_PAT` as environment variables. Many CI platforms (GitHub Actions, GitLab CI, CircleCI) have a native secrets store you can inject into the job environment.

### `cargo check` / build errors

Ensure your Rust toolchain is at least 1.86 (`rustup update stable`). Latch uses the 2024 edition.

### `latch status` shows all files as `!` (missing)

You have not exported the secrets locally yet. Run `latch export`.

### `latch run` exits with code 127 (command not found)

The program you specified is not in `$PATH`. Use the full path, or ensure the binary is installed.
