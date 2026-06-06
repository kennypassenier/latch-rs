.PHONY: bump-major bump-minor bump-patch show-version build build-linux ci-local install-hooks

show-version:
	@grep -m1 '^version = "' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/'

bump-major:
	@bash -ec '
	old=$$(grep -m1 "^version = \"" Cargo.toml | sed -E "s/version = \"([^\"]+)\"/\1/"); \
	IFS=. read -r major minor patch <<< "$$old"; \
	new="$$((major + 1)).0.0"; \
	sed -i -E "0,/^version = \"[^\"]+\"/s//version = \"$$new\"/" Cargo.toml; \
	echo "Bumped version: $$old -> $$new"'

bump-minor:
	@bash -ec '
	old=$$(grep -m1 "^version = \"" Cargo.toml | sed -E "s/version = \"([^\"]+)\"/\1/"); \
	IFS=. read -r major minor patch <<< "$$old"; \
	new="$$major.$$((minor + 1)).0"; \
	sed -i -E "0,/^version = \"[^\"]+\"/s//version = \"$$new\"/" Cargo.toml; \
	echo "Bumped version: $$old -> $$new"'

bump-patch:
	@bash -ec '
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

install-hooks:
	@mkdir -p .githooks
	@chmod +x .githooks/pre-commit
	@git config core.hooksPath .githooks
	@echo "Git hooks installed. Commits now run local CI preflight via pre-commit."

build: build-linux
	@rm -f ./latch && ln -s target/debug/latch ./latch
	@echo "Symlinked: ./latch -> target/debug/latch"
	@./target/x86_64-unknown-linux-gnu/release/latch path add
	@echo "Installed and registered: $$HOME/.local/bin/latch"
