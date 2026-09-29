#!/usr/bin/env bash
# Build and publish a latch release from this machine (Kenny, 2026-09-29:
# every build runs locally, GitHub only receives the result). It does what
# the release workflow did until then:
#
#   git tag v2.x.y && scripts/release.sh v2.x.y      # then scripts/sign-release.sh
#   DRY_RUN=1 scripts/release.sh v2.x.y              # build + verify, upload nothing
#
# 1. `make check`: what the CI workflow ran (gates, Windows tests, MSRV,
#    coverage);
# 2. latch-x86_64-unknown-linux-gnu, built in rust:1.97-bookworm (glibc 2.36,
#    the Debian 12 containers' own, so it starts there), and
#    latch-x86_64-pc-windows-msvc.exe, cross-built with cargo-xwin in its
#    docker image (the MSVC ABI the windows-latest runner produced);
# 3. SHA256SUMS over both;
# 4. push the tag and publish the release with the three assets. The
#    .minisig is added afterwards by scripts/sign-release.sh, as before.
set -euo pipefail
tag="${1:?usage: scripts/release.sh v2.x.y}"
repo="kennypassenier/latch-rs"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
dry="${DRY_RUN:-0}"

[ -z "$(git status --porcelain)" ] || { echo "release: working tree not clean" >&2; exit 1; }
if [ "$dry" != 1 ]; then
  [ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "release: not on main" >&2; exit 1; }
  git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "release: tag $tag does not exist. What now: git tag $tag" >&2; exit 1; }
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "$tag^{commit}")" ] || { echo "release: HEAD is not $tag" >&2; exit 1; }
fi
version="$(grep -m1 '^version = "' Cargo.toml | cut -d'"' -f2)"
[ "$dry" = 1 ] || [ "v$version" = "$tag" ] || { echo "release: tag $tag but Cargo.toml says $version" >&2; exit 1; }

make check

uid="$(id -u):$(id -g)"
caches=(-v "$HOME/.cargo/registry:/usr/local/cargo/registry" -v "$HOME/.cargo/git:/usr/local/cargo/git")
echo "== build x86_64-unknown-linux-gnu (rust:1.97-bookworm)"
docker run --rm --user "$uid" -e HOME=/tmp -e CARGO_HOME=/usr/local/cargo "${caches[@]}" \
  -v "$root:/src" -w /src rust:1.97-bookworm \
  cargo build --release --locked -p latch-cli --target x86_64-unknown-linux-gnu --target-dir target-release-linux
echo "== build x86_64-pc-windows-msvc (cargo-xwin)"
docker run --rm --user "$uid" -e HOME=/tmp -e XWIN_CACHE_DIR=/src/target-windows/xwin "${caches[@]}" \
  -v "$root:/src" -w /src messense/cargo-xwin \
  sh -c 'rustup target add x86_64-pc-windows-msvc >/dev/null 2>&1; cargo xwin build --release --locked -p latch-cli --target x86_64-pc-windows-msvc --target-dir target-release-windows'

rm -rf dist && mkdir -p dist
cp target-release-linux/x86_64-unknown-linux-gnu/release/latch dist/latch-x86_64-unknown-linux-gnu
cp target-release-windows/x86_64-pc-windows-msvc/release/latch.exe dist/latch-x86_64-pc-windows-msvc.exe
(cd dist && sha256sum latch-* > SHA256SUMS && cat SHA256SUMS)
dist/latch-x86_64-unknown-linux-gnu --version

if [ "$dry" = 1 ]; then
  echo "DRY_RUN: both binaries built and verified in dist/; nothing pushed or published"
  exit 0
fi
git push origin "$tag"
gh release create "$tag" --repo "$repo" --verify-tag --title "$tag" --notes "" \
  dist/latch-x86_64-unknown-linux-gnu dist/latch-x86_64-pc-windows-msvc.exe dist/SHA256SUMS
echo "released $tag. Next: scripts/sign-release.sh $tag"
