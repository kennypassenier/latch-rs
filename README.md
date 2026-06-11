# Latch — Encrypted Environment Secrets Management

[![Build Status](https://github.com/kennypassenier/latch-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/kennypassenier/latch-rs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Test Coverage: 24/26 use-cases](https://img.shields.io/badge/test%20coverage-24%2F26%20use--cases-brightgreen)](tests/use_case_checklist.rs)

Encrypted `.env` secrets management backed by a private GitHub repository.

Latch keeps your team's secrets out of application repositories by encrypting every `.env` file with a per-project (or per-environment) XChaCha20-Poly1305 key and storing the ciphertext in a dedicated secrets repository on GitHub. Team members pull and decrypt locally; CI/CD pipelines inject secrets directly into subprocesses without ever touching the filesystem.

---

## Features at a Glance

- **Zero-Trust Encryption** — XChaCha20-Poly1305 encryption with authenticated ciphertexts. Tampering is always detected.
- **Three-Step Workflow** — Separate `commit` (encrypt), `push` (upload), `pull` (download) phases for flexibility.
- **Offline-First** — Commit and rotate secrets without internet; sync when connectivity is restored.
- **Multi-Environment Keys** — Isolate dev, staging, and prod with separate encryption keys.
- **Clone Groups** — Multiple `.env` files can share one encrypted blob via pragmas.
- **Full Versioning** — GitHub commit history provides complete rollback via `latch history` and `latch rollback`.
- **Template Expansion** — Reference variables within `.env` files: `DATABASE_URL=postgres://${DB_HOST}:${DB_PORT}/db`
- **Example Generation** — Auto-generates `.env.example` files (keys only, no secrets).
- **Machine Clone** — Transfer full credential state between machines with end-to-end encryption.
- **Zero Disk** — `latch run` injects secrets into process memory; never touches filesystem.

---

## Quick Start (2 minutes)

```bash
# 1. Install from source
git clone https://github.com/kennypassenier/latch-rs
cd latch-rs && cargo install --path .

# 2. Global setup (one-time)
latch login
# → prompts for GitHub PAT and default secrets repo (owner/repo)

# 3. Initialize a project
cd ~/code/my-app
latch init
# → prompts for project name, environment, encryption key

# 4. Use the workflow
latch pull                  # Pull latest secrets
nano .env                   # Edit locally
latch commit                # Encrypt and stage locally (offline OK)
latch push                  # Upload to GitHub

# 5. Teammates pull the updates
latch pull
```

---

## Contents

- [Quick Start](#quick-start-2-minutes)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Setup](#setup)
  - [Global Configuration](#global-configuration)
  - [Per-Project Setup](#per-project-setup)
- [Commands Reference](#commands-reference)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Architecture](#architecture)
- [Release Process](#release-process)
- [Development & Testing](#development--testing)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Rust 1.86+** | `rustup update stable` or use pre-built binaries |
| **Private GitHub repository** | Dedicated to encrypted secrets only; never source code |
| **GitHub Personal Access Token (PAT)** | `repo` scope (read/write). [Create here](https://github.com/settings/tokens) |
| **OS keyring** (optional) | macOS Keychain, GNOME Keyring/KWallet, or Windows Credential Manager for secure key storage |

---

## Installation

### Option 1: Build from Source

```bash
git clone https://github.com/kennypassenier/latch-rs
cd latch-rs
cargo build --release
./target/release/latch --help

# Or install to your PATH
cargo install --path .
```

### Option 2: Download Pre-built Binary

Visit [Releases](https://github.com/kennypassenier/latch-rs/releases) and download the binary for your platform.

```bash
chmod +x latch
./latch path add   # Install to ~/.local/bin (Linux/macOS) or system PATH
```

### Option 3: Docker

```bash
docker run ghcr.io/kennypassenier/latch-rs:latest --help
```

### Verify Installation

```bash
latch --version
latch --help

# From now on, update in-place with the same command name
latch update
```

`latch update` currently downloads the Linux x86_64 release asset (`latch-linux-x86_64.tar.gz`),
extracts the executable named `latch`, and replaces your managed install path binary (for example `~/.local/bin/latch`).
Your command remains `latch` after every update.

---

## Setup

### Global Configuration

One-time setup to store GitHub credentials:

```bash
latch login
```

Prompts for:
1. **GitHub PAT** — Your personal access token (hidden input)
2. **Global encryption key** — 64-char hex or 44-char base64 key used to encrypt/decrypt
3. **Default secrets repo** — Format: `owner/repo` (defaults to `kennypassenier/secrets`)

You can also run non-interactively:

```bash
latch login -PAT ghp_xxx -KEY 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Credentials are stored in the OS keyring when available and always written to `~/.latch/config.toml` as a fallback for keyring-limited environments (for example LXC containers). If needed, environment variables still work:

```bash
export LATCH_PAT=gh_your_token_here
export LATCH_KEY=your_key_hex_or_base64
```

### Per-Project Setup

Initialize each application repository once:

```bash
cd ~/code/my-app
latch init
```

Prompts for:
1. **Project name** — Short identifier (e.g., `my-app`, `api`, `worker`)
2. **Default environment** — Usually `dev`
3. **Encryption key** — Generate random, derive from passphrase, or paste existing key

Creates:
- `.latch/config.toml` — Project metadata (✓ commit this)
- `.latchignore` — Exclusion patterns (✓ commit this)

### Link to Existing Project

If initializing against an existing project in your secrets repo:

```bash
latch project
```

Shows a selectable list of remote projects and lets you choose the one to link.

### Set Per-Environment Keys (Multi-Key Support)

After initialization, optionally set dedicated keys for specific environments:

```bash
latch key --env prod    # Production-only key
latch key --env staging # Staging-only key
```

This isolates access — only developers with the prod key can decrypt prod secrets.

---

## Commands Reference



### Automatic patch releases

Every push to `main` creates the next patch tag automatically:

1. If `Cargo.toml` is still at the latest released major/minor version, Latch creates the next patch tag.
2. The same pipeline creates the tag, then publishes a GitHub Release (binaries) and pushes a GHCR Docker image.

Example:

1. latest tag is `v1.4.2`
2. `Cargo.toml` still says `1.4.2`
3. push to `main`
4. automation creates `v1.4.3`
5. GitHub Release + Docker image are published for `v1.4.3`

### Manual major/minor releases

When you want to cut a new major or minor line, update `Cargo.toml` before merging:

```bash
make bump-minor
# or
make bump-major
```

After that change lands on `main`, the automation sees that `Cargo.toml` is ahead of the latest tag and creates that exact release tag instead of another automatic patch bump.

Example:

1. latest tag is `v1.4.3`
2. you run `make bump-minor` so `Cargo.toml` becomes `1.5.0`
3. merge to `main`
4. automation creates `v1.5.0`
5. GitHub Release + Docker image are published for `v1.5.0`

### Release artifacts

Each push to `main` publishes:

1. Linux, macOS, and Windows binaries on the GitHub Release page
2. Multi-arch Docker images to `ghcr.io/kennypassenier/latch-rs` (tags: `main`, `vX.Y.Z`, `vX.Y.Z.<run>`, `sha-<short>`)
3. Binary version metadata that matches the release tag



### Automatic patch releases

Every push to `main` creates the next patch tag automatically:

1. If `Cargo.toml` is still at the latest released major/minor version, Latch creates the next patch tag.
2. The same pipeline creates the tag, then publishes a GitHub Release (binaries) and pushes a GHCR Docker image.

Example:

1. latest tag is `v1.4.2`
2. `Cargo.toml` still says `1.4.2`
3. push to `main`
4. automation creates `v1.4.3`
5. GitHub Release + Docker image are published for `v1.4.3`

### Manual major/minor releases

When you want to cut a new major or minor line, update `Cargo.toml` before merging:

```bash
make bump-minor
# or
make bump-major
```

After that change lands on `main`, the automation sees that `Cargo.toml` is ahead of the latest tag and creates that exact release tag instead of another automatic patch bump.

Example:

1. latest tag is `v1.4.3`
2. you run `make bump-minor` so `Cargo.toml` becomes `1.5.0`
3. merge to `main`
4. automation creates `v1.5.0`
5. GitHub Release + Docker image are published for `v1.5.0`

### Release artifacts

Each push to `main` publishes:

1. Linux, macOS, and Windows binaries on the GitHub Release page
2. Multi-arch Docker images to `ghcr.io/kennypassenier/latch-rs` (tags: `main`, `vX.Y.Z`, `vX.Y.Z.<run>`, `sha-<short>`)
3. Binary version metadata that matches the release tag

---

## Per-Project Setup (Quick Reference)

What to commit to your app repo:

```
.latch/config.toml   ✓ commit
.latchignore         ✓ commit
.latch/              ✓ safe to commit  (encrypted blobs only)
.env                 ✗ never commit (add to .gitignore)
.env.example         ✓ commit (auto-generated by latch commit)
```

---



Secure credential migration between machines.

```
latch clone offer [--ttl-minutes 10]
latch clone create --offer-file ./offer.json [--stdout-file ./payload.json]
latch clone apply --payload-file ./payload.json
```

No-temp-files convenience (for agents):

```bash
# One-liner on target (generates offer, pipes to source)
latch clone offer | ssh user@source latch clone create --offer-stdin --stdout-file - | latch clone apply --stdin

# Or in steps (piped directly)
latch clone offer > >(ssh user@source 'cat > offer.json' && ssh user@source 'latch clone create --offer-file offer.json' > >(latch clone apply --stdin))
```

Typical flow:
1. Target machine (for example an LXC agent) runs `latch clone offer` and sends the JSON offer to the source machine.
2. Source machine runs `latch clone create` using that offer and sends the encrypted payload back.
3. Target machine runs `latch clone apply` to restore keyring entries and project metadata.

Automation-friendly options:
1. `latch clone create --offer-stdin` reads offer JSON from stdin (pipes directly from target offer generation).
2. `latch clone create --stdout-file ./payload.json` writes payload to a file while still printing JSON to stdout.
3. `latch clone apply --stdin` reads payload JSON from stdin (enables zero-file workflows).
4. `latch clone create --project my-app --project worker --env prod` limits exported credentials.
5. `latch clone create --verify-code <code>` adds an integrity tag; `latch clone apply --verify-code <code>` verifies it before decrypting.

What gets cloned:
1. Global keyring slots (`github.pat`, `github.secrets_repo`, `global.key`)
2. Project key slots (`<project>.key`, `<project>.key.<env>`)
3. Legacy project PAT slots (`<project>.pat`) when present
4. Project metadata entries in `~/.latch/config.toml`

Security notes:
1. Payloads are encrypted end-to-end using an ephemeral Diffie-Hellman exchange (x25519).
2. Offers expire automatically (default 10 minutes).
3. Applying a payload consumes and removes the local stored offer.
4. Optional one-time integrity verification is available via `--verify-code` on both create and apply.

---

### latch login

Store global credentials (PAT + KEY + default repo).

```
latch login [--PAT <token>] [--KEY <key>] [--REPO <owner/repo>]
```

Prompts for:
1. GitHub PAT
2. Global encryption key
3. Default secrets repo (`owner/repo`, default `kennypassenier/secrets`)

---

### latch init

Interactive project initialisation. Run once per project.

```
latch init
```

Creates `.latch/config.toml`, links this folder to a project, and pushes the initial manifest to the secrets repository when missing.

---

### latch project

Interactive project picker for the current folder.

```
latch project [--repo <owner/repo>] [--env <env>] [--list]
```

Default behavior (without flags):
1. Reads PAT + default repo from keyring.
2. Shows a selectable list of remote projects.
3. Lets you choose environment.
4. Writes `.latch/config.toml`.
5. Optionally runs `latch pull` immediately.

---

### latch commit

Encrypt local `.env` files and stage the ciphertexts in the local `.latch/` directory. **No network connection is required.** Only the encryption key is needed — not the GitHub PAT.

```
latch commit [--env <env>]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment label used as the local staging path prefix. |

**What it does:**
1. Walks the project tree using `.latchignore` rules. `.gitignore` does not suppress `.env` discovery.
2. Resolves clone groups (see [Clone groups](#clone-groups)). Subscribe-intent members read from the `.latch/` cache populated by a previous `latch pull`.
3. Encrypts each discovered `.env` file with XChaCha20-Poly1305.
4. Writes each ciphertext to `.latch/<env>/<flat-name>.enc`.
5. Generates a `.env.example` next to each `.env` file (values stripped, keys and comments kept).
6. Updates `.latch/staging.json` with the local manifest.

**Alias:** `lock`

**Example:**

```bash
# Stage dev secrets locally (no internet needed)
latch commit

# Stage production secrets
latch commit --env prod

# On a plane: commit first, push later when online
latch commit
# ... land, connect to wifi ...
latch push
```

---

### latch push

Upload staged encrypted blobs from `.latch/` to the secrets repository. Requires `latch commit` to have been run first. **No encryption key is needed** — only the GitHub PAT.

```
latch push [--env <env>]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment label to upload. |

**What it does:**
1. Reads `.latch/staging.json` to find what files are staged for the env.
2. Reads each `.latch/<env>/<flat-name>.enc` blob and uploads it to `<project>/<env>/<flat-name>.enc` in the secrets repository.
3. Removes stale remote encrypted files that were previously tracked but are no longer staged.
4. Updates the remote manifest.

If you deleted `.env` files locally and then ran `latch commit`, `latch push` will remove those stale encrypted files from the secrets repo as part of step 3.

**Alias:** `save`

**Example:**

```bash
# Push dev secrets
latch push

# Push production secrets
latch push --env prod
```

---

### latch pull

Pull ciphertext from the secrets repository, cache it to `.latch/`, and decrypt it to local `.env` files.

```
latch pull [--env <env>] [--dry-run] [--sparse]
latch pull sparse [--env <env>] [--dry-run]
```

| Flag | Default | Description |
|---|---|---|
| `--env` / `-e` | `dev` | Environment to pull from. |
| `--dry-run` | off | Print what would be written without touching the filesystem. |
| `--sparse` | off | Only write `.env` files whose parent directory already exists (useful for sparse checkouts). |

If a local `.env` file already exists and its content differs from the remote, Latch shows an inline diff and asks for confirmation before overwriting.

After pulling, encrypted blobs are cached to `.latch/<env>/` and `.latch/staging.json` is updated. This enables offline `latch commit` runs and allows subscribe-intent clone-group members to resolve from the local cache.

**Alias:** `unlock`

**Example:**

```bash
# Pull dev secrets
latch pull

# Preview what prod pull would do (no writes)
latch pull --env prod --dry-run

# Pull staging secrets
latch pull --env staging

# Sparse pull (only existing directories get files)
latch pull --sparse

# Equivalent sparse mode alias
latch pull sparse
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
| `~` | Modified — local differs from remote. Run `latch commit` then `latch push` to upload changes. |
| `!` | Missing locally — remote has this file but it does not exist locally. Run `latch pull` to pull it. |
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

After setting env-specific keys, `latch commit --env prod` encrypts with the prod key, and only someone with that key can run `latch pull --env prod`.

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

### latch update

Update to the latest published Latch release without changing your command name.

```
latch update
```

Current support:
1. Linux x86_64.
2. The downloaded asset is `latch-linux-x86_64.tar.gz`.
3. The installed executable is still named `latch`.

After one manual install to a managed PATH location, future updates can be done with `latch update`.

---

## Credential resolution

For each project, Latch looks for credentials in this order:

1. **Environment variable** (explicit key override) — `LATCH_KEY`
2. **OS keyring** (global key slot) — `global.key`
3. **`~/.latch/config.toml`** (global key fallback) — `global_key_hex`
4. **OS keyring** (env-specific key slot) — `<project>.key.<env>`
5. **OS keyring** (project-wide key slot) — `<project>.key`
6. **`~/.latch/config.toml`** (project key fallback) — `key_hex`
7. **OS keyring** (global PAT/repo slots) — `github.pat` and `github.secrets_repo`
8. **OS keyring** (legacy project PAT slot) — `<project>.pat`
9. **Environment/config PAT fallback** — `LATCH_PAT`, `global_pat`, `github_pat`

The first non-empty value wins.

---

## Environment variables

| Variable | Description |
|---|---|
| `LATCH_KEY` | Hex-encoded (64 chars) or base64-encoded (44 chars) 32-byte encryption key. |
| `LATCH_PAT` | GitHub Personal Access Token. |
| `RUST_LOG` | Control log verbosity. E.g. `RUST_LOG=debug latch commit`. |

These are especially useful in CI/CD where an OS keyring is unavailable.

---

## Configuration files

### `~/.latch/config.toml` (global)

Created automatically. Stores a list of known projects.

```toml
default_secrets_repo = "kennypassenier/secrets"
global_pat = "ghp_xxx"
global_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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

# One-time global login on your machine
latch login

# Link this folder to a project
latch project

# Pull dev secrets
latch pull
```

### CI/CD (GitHub Actions example)

```yaml
- name: Load secrets
  env:
    LATCH_KEY: ${{ secrets.LATCH_KEY_PROD }}
    LATCH_PAT: ${{ secrets.LATCH_PAT }}
  run: latch pull --env prod
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

`latch commit` will still discover and encrypt `.env` files even when they are gitignored.

### Stop tracking a previously encrypted file

If you add a path to `.latchignore`, then run:

```bash
latch commit --env dev
latch push   --env dev
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
  monorepo-api/dev/backend__.env.enc
  monorepo-worker/dev/worker__.env.enc
  monorepo-frontend/dev/frontend__.env.enc
```

### Strict prod access control (multi-key)

```bash
# After init (dev key is already set), add a separate prod key
latch key --env prod
# → prompts for a new key; stores it as "my-app.key.prod" in keyring

# Push prod secrets — encrypted with the prod key only
latch commit --env prod
latch push   --env prod

# Only engineers with the prod key can pull prod secrets
latch pull --env prod
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

You have not loaded the secrets locally yet. Run `latch pull`.

### `latch run` exits with code 127 (command not found)

The program you specified is not in `$PATH`. Use the full path, or ensure the binary is installed.

---

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Machine                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  .env files (plaintext)  ←→  Latch CLI                       │
│                                ├─ commit (XChaCha encrypt)   │
│                                ├─ push (upload to GitHub)    │
│                                ├─ pull (download + decrypt)  │
│                                └─ run (inject to subprocess) │
│                                                               │
│  .latch/ (encrypted blobs)                                   │
│  ├─ dev/backend__.env.enc                                    │
│  ├─ prod/backend__.env.enc                                   │
│  └─ staging.json (local manifest)                           │
│                                                               │
│  ~/.latch/ (global config)                                   │
│  └─ config.toml (projects list)                             │
│                                                               │
│  OS Keyring (encrypted credential storage)                   │
│  ├─ github.pat                                               │
│  ├─ my-app.key                                               │
│  └─ my-app.key.prod                                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                           ↕ HTTPS
┌─────────────────────────────────────────────────────────────┐
│        Private GitHub Repository (Secrets Vault)             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  my-app/dev/backend__.env.enc    (ciphertext only)          │
│  my-app/prod/backend__.env.enc   (ciphertext only)          │
│  my-app/manifest.json            (file tracking)            │
│                                                               │
│  (No plaintext secrets ever stored)                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Three-Step Workflow

1. **`latch commit`** — Encrypt locally with your key. Offline-safe.
2. **`latch push`** — Upload blobs to GitHub with PAT. No key needed.
3. **`latch pull`** — Download and decrypt locally. Cache for offline re-encryption.

This separation enables:
- Offline commits (no internet required)
- Secure key never leaves your machine
- CI/CD only needs PAT (no encryption key exposure)
- Clone groups to share secrets between `.env` files

### Encryption Pipeline

```
.env file (plaintext)
    ↓
XChaCha20-Poly1305 Cipher
    ├─ Random 24-byte nonce
    ├─ Your 32-byte key
    └─ AEAD authentication tag (16 bytes)
    ↓
.latch/<env>/<flat-name>.enc (ciphertext + nonce + tag)
    ↓
GitHub (encrypted storage)
```

### Clone Groups

Multiple `.env` files can share one encrypted blob via pragmas:

```dotenv
# backend/.env
# latch:group=database_config
DB_HOST=localhost
DB_PORT=5432
```

```dotenv
# migrations/.env
# latch:group=database_config
DB_USER=app_user
DB_PASS=secret123
```

Both files' values merge into one ciphertext. After `latch pull`, both directories have complete credentials from the cached blob.

### Key Storage

- **Primary:** OS keyring (macOS Keychain, GNOME Keyring/KWallet, Windows Credential Manager)
- **Fallback:** `LATCH_KEY` environment variable (CI/CD)
- **Fallback:** `key_hex` in `~/.latch/config.toml` (optional, not recommended)

Environment-specific keys are stored under `<project>.key.<env>` and take precedence over the project-wide key.

---

## Development & Testing

### Build from Source

```bash
git clone https://github.com/kennypassenier/latch-rs
cd latch-rs
cargo build --release
./target/release/latch --help
```

### Run Tests

```bash
# Install git hooks once (pre-commit runs ci-local and blocks failing commits)
make install-hooks

# CI-equivalent preflight (fmt + clippy + tests + msrv)
make ci-local

# Full test suite (111+ tests)
cargo test

# Use-case coverage checklist (validates all 26 use-cases have tests)
cargo test --test use_case_checklist -- --nocapture

# Run specific test file
cargo test --test cli_surface_tests

# With verbose output
RUST_LOG=debug cargo test
```

### Test Coverage

Latch has **24/26 implemented use-cases with automated test coverage**:

| Use-Case | Coverage | Status |
|----------|----------|--------|
| encryption | Full | ✅ roundtrip + tamper detection + wrong-key failure |
| path-flattening | Full | ✅ all variants tested (single/multi-level/.env.local) |
| template-expansion | Full | ✅ ${VAR} and $VAR patterns, self-references, unknown vars |
| multi-key-environments | Full | ✅ dev/prod isolation, per-env decryption |
| key-rotation | Full | ✅ old key invalid, all files re-encrypted |
| clone-groups | Strong Partial | ✅ pragma parsing, subscribe-intent, manifest roundtrip |
| machine-clone | Strong Partial | ✅ offer/create/apply roundtrip with verify-code |
| versioning | Strong Partial | ✅ history listing, rollback from ref |
| cli-scaffolding | Full | ✅ help pages, aliases, command structure |
| github-storage | Full | ✅ push/pull roundtrip, delete, history |
| ... *(20+ more)* | — | See [use_case_checklist.rs](tests/use_case_checklist.rs) for full report |

Run the checklist:

```bash
cargo test --test use_case_checklist -- --nocapture
```

### Code Organization

```
src/
  ├─ main.rs           # CLI entry point
  ├─ lib.rs            # Library exports
  ├─ error.rs          # Error types
  │
  ├─ commands/         # Command implementations
  │  ├─ commit.rs      # Encrypt & stage
  │  ├─ push.rs        # Upload to GitHub
  │  ├─ pull.rs        # Download & decrypt
  │  ├─ run.rs         # Inject to subprocess
  │  ├─ clone.rs       # Machine credential transfer
  │  ├─ rotate.rs      # Key re-encryption
  │  ├─ history.rs     # Version listing
  │  ├─ rollback.rs    # Restore old secrets
  │  └─ ...
  │
  ├─ config/           # Configuration
  │  ├─ global.rs      # ~/.latch/config.toml
  │  ├─ project.rs     # .latch/config.toml
  │  └─ mod.rs
  │
  ├─ crypto/           # Encryption
  │  ├─ kdf.rs         # Argon2id key derivation
  │  └─ mod.rs         # XChaCha20-Poly1305 wrapper
  │
  ├─ manifest/         # Manifest management
  ├─ credentials/      # Key resolution chain
  ├─ discovery/        # .env scanning
  └─ github/           # GitHub API client

tests/
  ├─ use_case_checklist.rs     # v1.0.0 release validation
  ├─ cli_surface_tests.rs      # CLI + machine-clone E2E
  ├─ command_integration.rs    # Full workflow tests
  ├─ crypto_tests.rs           # Encryption validation
  ├─ config_tests.rs           # Configuration logic
  └─ regression_vectors.rs     # Stability tests
```

### Dependencies

Key crates:
- **clap** — CLI argument parsing
- **chacha20poly1305** — AEAD encryption
- **x25519-dalek** — Ephemeral Diffie-Hellman (machine-clone)
- **argon2** — Key derivation from passphrases
- **tokio** — Async runtime
- **serde** — Serialization (JSON, TOML)
- **rusty-hook** — Git integration

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make changes and write tests
4. Run full test suite (`cargo test`)
5. Commit with conventional messages (`feat:`, `fix:`, `docs:`)
6. Submit a pull request

### Debugging

Enable debug logging:

```bash
RUST_LOG=debug latch commit
RUST_LOG=trace latch pull
```

Test-specific debugging:

```bash
cargo test -- --nocapture              # See println! output
cargo test -- --test-threads=1         # Sequential test execution (easier to follow)
```

---

## License

MIT — See [LICENSE](LICENSE) for details.

---

## Support & Questions

- **GitHub Issues** — [Report bugs and request features](https://github.com/kennypassenier/latch-rs/issues)
- **Discussions** — [Ask questions and share ideas](https://github.com/kennypassenier/latch-rs/discussions)
- **Security** — For security advisories, email the maintainer directly

---

**v1.0.0 Ready** — 24/26 implemented use-cases with full automated test coverage. See [tests/use_case_checklist.rs](tests/use_case_checklist.rs) for comprehensive release validation.

