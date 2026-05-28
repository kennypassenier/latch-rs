.PHONY: bump-major bump-minor bump-patch show-version

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
