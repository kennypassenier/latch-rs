#!/usr/bin/env bash
# latch v2 quality gates (standing rule 7) — called by check-commit.sh
# before every git commit; non-zero exit blocks the commit. The legacy
# package (AR14) is frozen reference and deliberately ungated.
set -euo pipefail

# Git exports GIT_DIR, GIT_INDEX_FILE and friends to a hook, as absolute
# paths when the commit is made in a linked worktree. A test that runs git
# in a fixture directory then acts on THIS repository: on 2026-09-29 the
# escrow tests committed fixtures onto the branch being committed and
# emptied its index. Drop them, as kp-themes-tui and kyu do.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_COMMON_DIR

# ── Standing rule 7: a gate that does not predict the build is not a gate ──
# The checks below rewrite files. cargo updates Cargo.lock, formatters
# rewrite sources — and anything rewritten AFTER `git add` is green here
# and absent from the commit. mailbox's 1.0.0 commit carried a lock file
# still naming version 0.0.0; the container build refused it one step
# before a release tag, and nothing local had objected. So: fingerprint
# the tree now, compare once the checks are done, and refuse rather than
# report a green run over a tree that moved underneath it.
gate_tree_fingerprint() {
  { git status --porcelain; git diff; } | sha256sum | cut -d' ' -f1
}
gate_tree_before=$(gate_tree_fingerprint)
# Kenny, 2026-09-16, standing rule 49 (commit-floor and rust-suite):
# format and lint always run, and the suite is skipped when no Rust
# source moved. Measured across sixteen projects: 41% of commits touch
# only documentation or configuration and paid for the suite anyway. Per
# crate was measured and rejected — `cargo test -p <crate>` is not faster
# than the whole workspace, because cargo runs every test binary either
# way.
. "$(git rev-parse --show-toplevel)/.githooks/gate-cache.sh"

cargo fmt -p latch-core -p latch-cli -p latch-ui -- --check
cargo clippy -p latch-core -p latch-cli -p latch-ui --all-targets -- -D warnings
gate_glob suite '*.rs' 'Cargo.toml' 'Cargo.lock' '*/Cargo.toml' -- \
  cargo test -p latch-core -p latch-cli -p latch-ui

gate_cache_done

# Standing rule 7, second clause: see gate_tree_fingerprint above.
if [ "$(gate_tree_fingerprint)" != "$gate_tree_before" ]; then
  {
    echo "gates: the checks rewrote the working tree while they ran."
    echo "A file changed after it was staged, so what this commit carries is"
    echo "NOT what was just tested. Most often this is cargo refreshing"
    echo "Cargo.lock; the changed paths are listed below."
    echo
    git status --porcelain
    echo
    echo "What now: run 'git add -A' and commit again."
  } >&2
  exit 1
fi
