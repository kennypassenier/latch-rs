#!/usr/bin/env bash
# latch v2 quality gates (standing rule 7) — called by check-commit.sh
# before every git commit; non-zero exit blocks the commit. The legacy
# package (AR14) is frozen reference and deliberately ungated.
set -euo pipefail
cargo fmt -p latch-core -p latch-cli -p latch-ui -- --check
cargo clippy -p latch-core -p latch-cli -p latch-ui --all-targets -- -D warnings
cargo test -p latch-core -p latch-cli -p latch-ui
