#!/usr/bin/env bash
# D4 release signing (Garuda / any Linux). Run AFTER the release workflow
# has published the binaries + SHA256SUMS for a tag. Downloads the
# manifest, signs it with your OFFLINE minisign secret key, and uploads
# SHA256SUMS.minisig to the release. Your secret key never touches GitHub.
#
# Usage:  scripts/sign-release.sh v2.0.0  [~/.minisign/minisign.key]
set -euo pipefail
tag="${1:?usage: sign-release.sh <tag> [secret-key]}"
key="${2:-$HOME/.minisign/minisign.key}"
repo="kennypassenier/latch-rs"

command -v minisign >/dev/null || { echo "install minisign (pacman -S minisign)"; exit 1; }
command -v gh >/dev/null || { echo "install the GitHub CLI (gh)"; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh release download "$tag" -R "$repo" -p SHA256SUMS -D "$tmp"
minisign -S -m "$tmp/SHA256SUMS" -s "$key" -x "$tmp/SHA256SUMS.minisig"
gh release upload "$tag" "$tmp/SHA256SUMS.minisig" -R "$repo" --clobber
echo "✓ signed and uploaded SHA256SUMS.minisig for $tag"
