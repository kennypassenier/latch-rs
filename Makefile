# Define the target OS and glibc version to match Proxmox Debian 12 LXC containers
LXC_BUILD_IMAGE ?= debian:12-slim
LXC_GLIBC_VERSION = 2.36

.PHONY: bump-major bump-minor bump-patch show-version build build-linux ci-local check release install-hooks build-lxc

show-version:
	@grep -m1 '^version = "' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/'

bump-major:
	@bash -ec ' \
	old=$$(grep -m1 "^version = \"" Cargo.toml | sed -E "s/version = \"([^\"]+)\"/\1/"); \
	IFS=. read -r major minor patch <<< "$$old"; \
	new="$$((major + 1)).0.0"; \
	sed -i -E "0,/^version = \"[^\"]+\"/s//version = \"$$new\"/" Cargo.toml; \
	echo "Bumped version: $$old -> $$new"'

bump-minor:
	@bash -ec ' \
	old=$$(grep -m1 "^version = \"" Cargo.toml | sed -E "s/version = \"([^\"]+)\"/\1/"); \
	IFS=. read -r major minor patch <<< "$$old"; \
	new="$$major.$$((minor + 1)).0"; \
	sed -i -E "0,/^version = \"[^\"]+\"/s//version = \"$$new\"/" Cargo.toml; \
	echo "Bumped version: $$old -> $$new"'

bump-patch:
	@bash -ec ' \
	old=$$(grep -m1 "^version = \"" Cargo.toml | sed -E "s/version = \"([^\"]+)\"/\1/"); \
	IFS=. read -r major minor patch <<< "$$old"; \
	new="$$major.$$minor.$$((patch + 1))"; \
	sed -i -E "0,/^version = \"[^\"]+\"/s//version = \"$$new\"/" Cargo.toml; \
	echo "Bumped version: $$old -> $$new"'

build-linux:
	@cargo build --release --locked --target x86_64-unknown-linux-gnu
	@echo "Built: target/x86_64-unknown-linux-gnu/release/latch"

ci-local:
	@echo "[1/4] rustfmt check"
	@cargo fmt --all -- --check
	@echo "[2/4] clippy (deny warnings)"
	@RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features -- -D warnings
	@echo "[3/4] test suite"
	@cargo test --locked
	@echo "[4/4] msrv check (Rust 1.86)"
	@cargo +1.86 check --locked
	@echo "Local CI preflight passed"

# What the CI workflow ran on every push until 2026-09-29, when Kenny moved
# every build and check to his own machine ("alle builds lokaal"). The
# release runs it first. The gates run in full (no cache skip); the Windows
# suites run on real Windows through WSL interop and refuse on a machine
# without it unless WINDOWS_TESTS=skip says so out loud; the MSRV build runs
# in the rust:1.86 image, so no toolchain has to be installed for it;
# coverage is informational, as it was, and runs where cargo-llvm-cov is.
WIN_SUITES := -p latch-core --test fix_win_keyring_1_tests --test fix_win_paths_1_tests --test fix_win_update_1_tests
check:
	@echo "[1/4] gates (fmt, clippy -D warnings, tests)"
	@# One full test run per release (Kenny, 2026-09-29): skipped when the
	@# commit gate stamped exactly this tree green (workstation/bin/gate-stamp).
	@if [ -x $(HOME)/Projects/workstation/bin/gate-stamp ] && $(HOME)/Projects/workstation/bin/gate-stamp fresh; then \
		echo "  already green on this tree at commit (gate-stamp)"; else GATE_FULL=1 .claude/hooks/gates.sh; fi
	@echo "[2/4] Windows: build + credential store round trip, paths, update"
	@if [ "$(WINDOWS_TESTS)" = skip ]; then echo "  SKIPPED on request (WINDOWS_TESTS=skip)"; \
	else scripts/windows-tests.sh $(WIN_SUITES) || { rc=$$?; [ $$rc -eq 3 ] && echo "  no Windows here; rerun on WSL, or WINDOWS_TESTS=skip to go without" >&2; exit $$rc; }; fi
	@echo "[3/4] MSRV build (Rust 1.86, rust:1.86 image)"
	@docker run --rm --user $$(id -u):$$(id -g) -e HOME=/tmp -e CARGO_HOME=/usr/local/cargo \
		-v $(HOME)/.cargo/registry:/usr/local/cargo/registry -v $(HOME)/.cargo/git:/usr/local/cargo/git \
		-v $(CURDIR):/src -w /src -e RUSTUP_TOOLCHAIN=1.86 rust:1.86 \
		cargo build --locked -p latch-core -p latch-cli -p latch-ui --target-dir target-msrv
	@echo "[4/4] coverage (informational)"
	@if command -v cargo-llvm-cov >/dev/null; then cargo llvm-cov -p latch-core -p latch-cli -p latch-ui --summary-only; \
	else echo "  skipped: cargo-llvm-cov not installed (cargo install cargo-llvm-cov)"; fi
	@echo "check passed"

# scripts/release.sh builds both binaries here and publishes them; see its
# header. `make release TAG=v2.x.y` (DRY_RUN=1 to rehearse).
release:
ifndef TAG
	$(error usage: make release TAG=v2.x.y)
endif
	scripts/release.sh $(TAG)

install-hooks:
	@mkdir -p .githooks
	@chmod +x .githooks/pre-commit .githooks/commit-msg
	@git config core.hooksPath .githooks
	@echo "Git hooks installed: pre-commit runs .claude/hooks/gates.sh,"
	@echo "commit-msg requires feature IDs in the message."

build: build-linux
	@rm -f ./latch && ln -s target/debug/latch ./latch
	@echo "Symlinked: ./latch -> target/debug/latch"
	@./target/x86_64-unknown-linux-gnu/release/latch path add
	@echo "Installed and registered: $$HOME/.local/bin/latch"

build-lxc:
	@echo "Starting isolated LXC compatible build..."
	@echo "Target environment: $(LXC_BUILD_IMAGE) (glibc $(LXC_GLIBC_VERSION))"
	docker run --rm \
		--volume "$(PWD):/workspace" \
		--workdir /workspace \
		$(LXC_BUILD_IMAGE) \
		sh -c "apt-get update -y && \
		       apt-get install -y --no-install-recommends ca-certificates curl build-essential libssl-dev pkg-config && \
		       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
		       . \$$HOME/.cargo/env && \
		       cargo build --release"
	@echo "Build complete. Binary available at target/release/latch"