# Latch-Rs: Exhaustive Testing Strategy (Mock-Based)

To test Latch-Rs without requiring live GitHub credentials or real secrets, we utilize a combination of dependency injection, mocking, and local filesystem sandboxing.

## 1. Core Testing Methodology
* **Dependency Injection:** The `GitHubClient` and `Keyring` traits should be defined in Rust. In production, they interface with the real Octocrab and OS keyring; in tests, we provide `MockGitHubClient` and `MockKeyring` implementations.
* **Filesystem Sandboxing:** All tests use `tempfile` to create isolated, disposable root directories, preventing `~/.latch/` contamination.
* **Environment Simulation:** Use `std::env::set_var` to inject mock configurations (e.g., `LATCH_KEY` for decryption tests).

## 2. Unit Testing Layers

### Crypto Layer (`src/crypto/`)
* **Roundtrip Integrity:** Generate a random 32-byte key, encrypt a payload (test `.env` file content), and ensure decryption produces exact byte-for-byte equality.
* **Nonce Randomness:** Verify that encrypting the same file twice results in different ciphertexts (due to randomized nonces).
* **Tamper Proofing:** Manually modify one byte in the ciphertext (the `nonce` or `ciphertext` part) and assert that the `chacha20poly1305` tag validation fails (`DecryptError`).
* **KDF Validation:** Given a known salt and password, assert that the derived key matches a pre-computed Argon2id output.

### Config & Manifest (`src/config/`, `src/manifest/`)
* **Hierarchy Traversal:** Create a dummy directory structure `a/b/c/d/`. Place `.latch.toml` in `a/`. Run `find_and_load()` from `d/` and assert it correctly resolves `a/`.
* **Manifest Parsing:** Load a malformed `manifest.json` and verify the parser returns the expected custom error rather than panicking.

## 3. Integration Testing (Mocked IO)
* **Command Emulation:** Create a test suite that invokes the `main()` function entry point with `Vec<String>` arguments.
* **Mocked GitHub:**
  * Define a `TestRepo` struct that maintains a `HashMap<PathBuf, Vec<u8>>` in memory.
  * Implement `get_file` and `put_file` for `TestRepo` that simply read/write to the `HashMap`.
  * **Test Case:** Run `latch push` -> Ensure the `HashMap` contains the correct file structure.
  * **Test Case:** Run `latch export` -> Ensure the mock repo returns the bytes, and the tool writes the correct decrypted files to the local temp directory.

## 4. Subprocess Testing (`latch run`)
* **Environment Injection:** Use `latch run --env=dev -- printenv` (or a mock target that prints its own environment variables to a file).
* **Validation:** Assert that the resulting environment contains the decrypted secrets.
* **Leak Check:** Verify that stdout/stderr of the `latch` process itself does not contain the decrypted key-value pairs.

## 5. Security & Edge Case Testing
* **Empty Keys:** Test behavior when `LATCH_KEY` is unset or malformed (base64 vs hex).
* **Empty Manifest:** Run `export` against an empty manifest or a missing `manifest.json` to ensure user-friendly error messages (e.g., "Run latch init first").
* **Target Collision:** Simulate two different `.env` files trying to write to the same target directory and ensure the tool handles (or refuses) the conflict.
* **Binary Integrity:** Verify the "LTCH" magic bytes on the start of files. Attempt to decrypt a "fake" file (not encrypted by Latch) and verify the code errors out gracefully.

## 6. Makefile & Build Verification
* **Target Simulation:** Since we cannot easily build cross-platform binaries in CI without Docker, test that the Makefile correctly resolves paths and triggers `cargo build` for the local architecture.
* **Artifact check:** Add a test step that checks if the `dist/` directory exists and contains the expected binary name after a successful `make`.

## 7. Recommended Test Suite Structure
```text
tests/
  ├── crypto_tests.rs      # Independent crypto math
  ├── config_tests.rs      # Path resolution logic
  ├── integration_mocks.rs # MockGitHubClient + TempFS
  └── cli_tests.rs         # Execution of binary main() via subprocess