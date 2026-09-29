#!/usr/bin/env bash
# Run test suites on real Windows from Linux (Kenny, 2026-09-29: every check
# runs locally; this replaces the `windows` job of the old CI workflow).
#
#   scripts/windows-tests.sh <cargo test args…>
#   e.g. scripts/windows-tests.sh -p latch-core --test fix_win_keyring_1_tests
#
# The test binaries are cross-built for x86_64-pc-windows-msvc with
# cargo-xwin in its docker image, then executed through WSL's Windows
# interop, so they run against the real Windows credential store and paths.
# Where there is no Windows next door (Garuda), the build still proves the
# Windows code compiles, and the script says loudly that the tests did NOT
# run: exit code 3, never a silent pass.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
[ "$#" -gt 0 ] || { echo "usage: scripts/windows-tests.sh <cargo test args…>" >&2; exit 2; }

# Tests find their fixtures through env!("CARGO_MANIFEST_DIR"), baked in at
# compile time. In the container that is /src/<crate>, which means nothing to
# Windows, so a rustc wrapper rewrites it, for the Windows target only, to the
# \\wsl.localhost\<distro>\... path Windows reaches this checkout by
# (wslpath -w).
mkdir -p target-windows
wsl_root=""
command -v wslpath >/dev/null && wsl_root="$(wslpath -w "$root")"
cat > target-windows/rustc-wrapper.sh <<'WRAP'
#!/bin/sh
case " $* " in
  *" --target x86_64-pc-windows-msvc "*)
    if [ -n "$WIN_ROOT" ]; then
      # CARGO_MANIFEST_DIR, CARGO_TARGET_TMPDIR and every CARGO_BIN_EXE_<name> an integration
      # test uses to find the binary it drives.
      for v in $(env | sed -n 's/^\(CARGO_MANIFEST_DIR\|CARGO_TARGET_TMPDIR\|CARGO_BIN_EXE_[A-Za-z0-9_-]*\)=\/src.*/\1/p'); do
        eval "val=\$$v"
        export "$v=$WIN_ROOT$(printf '%s' "${val#/src}" | tr / '\\')"
      done
    fi ;;
esac
exec "$@"
WRAP
chmod +x target-windows/rustc-wrapper.sh

uid="$(id -u):$(id -g)"
out=$(docker run --rm --user "$uid" -e HOME=/tmp -e XWIN_CACHE_DIR=/src/target-windows/xwin \
  -e RUSTC_WRAPPER=/src/target-windows/rustc-wrapper.sh -e WIN_ROOT="$wsl_root" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry" -v "$HOME/.cargo/git:/usr/local/cargo/git" \
  -v "$root:/src" -w /src messense/cargo-xwin \
  sh -c 'rustup target add x86_64-pc-windows-msvc >/dev/null 2>&1; cargo xwin test --no-run --locked --target x86_64-pc-windows-msvc --target-dir target-windows --message-format=json "$@"' sh "$@")
exes=$(printf '%s\n' "$out" | python3 -c '
import json, sys
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
        print(m["executable"])')
[ -n "$exes" ] || { echo "windows-tests: the build produced no test binary" >&2; exit 1; }

if ! grep -qs enabled /proc/sys/fs/binfmt_misc/WSLInterop; then
  echo "windows-tests: built for Windows, but NOT RUN: no Windows interop on this machine (WSL only)." >&2
  exit 3
fi
fail=0
while read -r exe; do
  local_exe="$root/${exe#/src/}"
  echo "== $(basename "$local_exe")"
  INSTA_UPDATE=no INSTA_WORKSPACE_ROOT="$wsl_root" WSLENV="INSTA_UPDATE:INSTA_WORKSPACE_ROOT${WSLENV:+:$WSLENV}" "$local_exe" </dev/null || fail=1
done <<< "$exes"
exit $fail
