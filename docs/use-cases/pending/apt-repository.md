# APT repository and unattended updates

**Status:** Pending  
**Category:** Distribution / Installation

## Summary

Publish Latch as a signed APT repository hosted on GitHub Pages so that Debian/Ubuntu/Proxmox
users can install and update via standard `apt` tooling, including unattended-upgrades.

## User Story

As a Proxmox host operator running Latch on Debian, I want to add a single APT source entry
and have `apt update && apt upgrade` (or unattended-upgrades) keep Latch up to date
automatically — the same way I update any other system package.

## Acceptance Criteria

- Each CI release produces a signed `.deb` package (`latch_x.y.z_amd64.deb`).
- The `.deb` installs the `latch` binary to `/usr/local/bin/latch` and registers it on PATH.
- A signed APT repository (Packages, Release, InRelease files) is published to the
  `gh-pages` branch of this repo, served via GitHub Pages.
- A GPG signing key (private key stored as a GitHub Actions secret) signs the `Release` file.
- The public GPG key is downloadable from a stable URL (e.g. the GitHub Pages root).
- `unattended-upgrades` picks up new versions automatically once the apt source is configured.
- A one-time setup snippet is documented so any Debian-based host can onboard.

## Intended install flow (one-time on each host)

```bash
# 1. Add the signing key
curl -fsSL https://kennypassenier.github.io/latch-rs/latch.gpg \
  | gpg --dearmor \
  | sudo tee /etc/apt/keyrings/latch.gpg > /dev/null

# 2. Add the APT source
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/latch.gpg] \
  https://kennypassenier.github.io/latch-rs stable main" \
  | sudo tee /etc/apt/sources.list.d/latch.list

# 3. Install
sudo apt update
sudo apt install latch
```

## Intended update flow (unattended or manual)

```bash
# Manual
sudo apt update && sudo apt upgrade latch

# Unattended — no extra config needed once the apt source is in place.
# unattended-upgrades will pick up new versions on its normal schedule.
```

## Required implementation work

1. **Debian packaging** — add `debian/` control files (control, changelog, rules, compat) or a
   `cargo-deb` config in `Cargo.toml`.
2. **CI: build .deb** — extend the `build-binaries` job (or add a new job) that calls
   `cargo-deb` and produces `latch_x.y.z_amd64.deb`.
3. **CI: sign .deb** — use `dpkg-sig` or `debsigs` with a GPG key stored in Actions secrets.
4. **CI: update APT repo** — check out `gh-pages`, run `dpkg-scanpackages`, `apt-ftparchive`,
   and `gpg --clearsign` to regenerate Packages/Release/InRelease, then push back.
5. **GitHub Pages** — enable on the repo (or use an existing branch).
6. **GPG key management** — generate a dedicated signing keypair; store private key as
   `APT_SIGNING_KEY` secret; publish armoured public key at `/latch.gpg` on Pages.
7. **README** — add "Install via APT" section with the one-time setup snippet above.
8. **unattended-upgrades compatibility** — verify the `Origin`/`Suite` fields in the Release
   file satisfy unattended-upgrades' default allowed-origins pattern, or document the required
   `/etc/apt/apt.conf.d/` snippet.

## Notes

- GitHub Pages URL is `https://kennypassenier.github.io/latch-rs/` (free, no extra hosting).
- Only `amd64` (x86_64) is needed to start; `arm64` can be added later if needed.
- Unattended-upgrades will update latch on its normal schedule (typically nightly) once
  the apt source is added — no extra cron or configuration needed on Proxmox.
- Once this is live, `latch update` remains available for users who prefer the binary-only
  install path. The two mechanisms are independent.
