# Latch-Rs Features & Implementation Plan

## 1. Core Configuration & CLI Scaffolding
* [x] **1.1. CLI Entry Point & Subcommands**
  * **Task:** Setup `clap` with `login`, `init`, `project`, `save`, and `load` subcommands. Add global flags (e.g., `--verbose`, `--env`).
  * **Test:** Run CLI with `--help` and verify subcommands. Unit test argument parsing for correct struct generation.
* [x] **1.2. Global Config Loader (`~/.latch/config.toml`)**
  * **Task:** Create `GlobalConfig` struct. Write functions to ensure the `~/.latch/` directory exists and load/save the TOML.
  * **Test:** Unit test with a mock home directory to verify TOML serialization and default creation.
* [x] **1.3. Project Config Loader (`.latch/config.toml`)**
  * **Task:** Create `ProjectConfig` struct (repo name, default env). Write logic to find `.latch/` in the current or parent directories.
  * **Test:** Create a nested temp directory structure, place `.latch/` at the root, and verify the loader finds it from a child directory.

## 2. Secure Credential Management
* [x] **2.1. Credential Trait Definition**
  * **Task:** Define a `CredentialProvider` trait with `get_pat()`, `get_key()`, `set_credentials()`.
  * **Test:** Compile check. No runtime tests needed for the trait itself.
* [x] **2.2. Environment Variable Fallback (CI/CD Support)**
  * **Task:** Implement `EnvVarProvider` that reads `LATCH_PAT` and `LATCH_KEY`. This is crucial for headless environments.
  * **Test:** `std::env::set_var`, call the provider, assert values match, then clean up the environment variables.
* [x] **2.3. OS Keyring Integration**
  * **Task:** Implement `KeyringProvider` using the `keyring` crate. Namespace it by `$projectname` so multiple projects don't collide.
  * **Test:** Implement a `MockKeyringProvider` using an in-memory `HashMap` to test fallback logic (try OS Keyring -> fallback to Env Vars).

## 3. Auto-Discovery & File Handling
* [x] **3.1. Ignore File Parser**
  * **Task:** Use the `ignore` crate to parse `.gitignore` and a custom `.latchignore`.
  * **Test:** Create a temp dir with a `.gitignore` ignoring `secret.env`. Verify the walker skips it.
* [x] **3.2. Recursive `.env` Scanner**
  * **Task:** Walk the directory respecting the ignore rules. Collect `PathBuf` for every `.env` found.
  * **Test:** Setup a temp tree with `.env` files at various depths. Assert the returned vector matches the expected paths exactly.
* [x] **3.3. Path Name Flattening**
  * **Task:** Convert local paths (e.g., `src/backend/.env`) to flat schema (`src.backend.env`).
  * **Test:** Unit test the path manipulation string functions with Windows (`\`) and Unix (`/`) separators.
* [x] **3.4. Example Generator (`.env.example`)**
  * **Task:** Parse `.env` lines, split by `=`, discard the value, write the key to `.env.example`.
  * **Test:** Provide a mock `.env` with comments, empty lines, and complex values. Assert the resulting `.env.example` only contains keys and retains comments.

## 4. Cryptography Engine (XChaCha20-Poly1305)
* [x] **4.1. Key Derivation & Nonce Generation**
  * **Task:** Setup Argon2id or a direct SHA-256 hash if user provides a raw string to ensure exactly 32 bytes for XChaCha20. Write a secure 24-byte random nonce generator.
  * **Test:** Assert nonces are exactly 24 bytes and consecutive calls yield different nonces.
* [x] **4.2. Encrypt & Decrypt Functions**
  * **Task:** Implement standard AEAD encrypt/decrypt wrappers. Prepend the 24-byte nonce to the resulting ciphertext.
  * **Test:** Roundtrip test: Encrypt a byte array, decrypt it, assert equality.
* [x] **4.3. Cryptographic Tamper Test**
  * **Task:** Ensure Poly1305 MAC works.
  * **Test:** Encrypt data, flip the last bit of the ciphertext, assert decryption throws a specific `MacError`.

## 5. GitHub API Integration
* [x] **5.1. GitHub Client Wrapper & Trait**
  * **Task:** Define `RemoteStorage` trait (`push_file`, `pull_file`). Wrap `reqwest` or `octocrab`.
  * **Test:** Create a `MockRemoteStorage` that writes to a local `HashMap` instead of making HTTP calls.
* [x] **5.2. Payload Builder**
  * **Task:** Format the GitHub API JSON payload (requires base64 encoding the content and providing commit messages).
  * **Test:** Unit test the serialization of the payload to ensure base64 formatting matches GitHub's API specs.
* [x] **5.3. Conflict Handling (SHA matching)**
  * **Task:** When updating a file via GitHub API, you must provide the file's current SHA blob. Implement logic to fetch the SHA before pushing.
  * **Test:** Mock the fetch-SHA response and assert the subsequent push payload includes the correct `sha` field.

## 6. Manifest & Workflows
* [x] **6.1. Manifest Builder**
  * **Task:** Structs for `manifest.json`. Logic to map flat filenames to local directory targets.
  * **Test:** Serialize/Deserialize tests to ensure JSON structure remains stable.
* [x] **6.2. The `latch init` Command**
  * **Task:** Interactive prompts (using `dialoguer`) for GitHub PAT, repo name, and encryption key. Save to Keyring and `.latch/config.toml`.
  * **Test:** Mock user inputs. Assert the keyring mock receives the secrets and the `.latch/` directory is scaffolded correctly.
* [x] **6.3. The `latch save --env=dev` Command**
  * **Task:** Chain: Discovery -> Example Generation -> Encryption -> Manifest Update -> GitHub Push.
  * **Test:** Integration test using temp directory + `MockKeyringProvider` + `MockRemoteStorage`. Assert the mock remote receives the encrypted files and updated manifest.
* [x] **6.4. The `latch load --env=dev` Command**
  * **Task:** Chain: Fetch Manifest -> Pull Encrypted files -> Decrypt -> Recreate local directories -> Write `.env` files.
  * **Test:** Seed `MockRemoteStorage` with encrypted files. Run load. Assert the `.env` files appear in the correct local temp directories with correct decrypted content.

## 7. UX & Polish
* [x] **7.1. Overwrite Protection (Diffing)**
  * **Task:** Before `load` overwrites a local `.env`, check if the local file differs from what we are about to write.
  * **Test:** Place a modified `.env` in the temp dir. Run load, assert it errors or prompts for override.
* [x] **7.2. Progress Bars & Logging**
  * **Task:** Integrate `indicatif` for progress bars during GitHub uploads/downloads. Use `tracing` for debug logs.
  * **Test:** Visual manual verification. (Unit testing progress bars is notoriously flaky, skip strict assertions here).

## 8. Completed Roadmap Items (Delivered)
- [x] **8.1. Secret Rotation (`latch rotate`)**
  * **Task:** Create a command to download all secrets, decrypt them with the current key, encrypt them with a new key, upload them, and update the local Keyring.
  * **Test:** Run rotation with a mock storage, assert the old key fails to decrypt the new payload and the new key succeeds.
- [x] **8.2. Diffing and Status (`latch status`)**
  * **Task:** Compare local `.env` files against the remote repository state and output a clean diff showing what is out of sync without making modifications.
  * **Test:** Modify a local file, run status, and assert the output correctly highlights the altered lines or files.
- [x] **8.3. Subprocess Injection (`latch run`)**
  * **Task:** Intercept process execution (e.g., `latch run node index.js`) and inject decrypted secrets directly into its memory environment, bypassing the filesystem entirely.
  * **Test:** Execute a dummy script that prints its environment, assert the secrets are present in the output but absent from the host filesystem.
- [x] **8.4. Template Referencing**
  * **Task:** Allow `.env` files to resolve other internal variables (e.g., `DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@localhost:5432`).
  * **Test:** Feed a template `.env` to the parser and assert the resulting values have variables correctly expanded.
- [x] **8.5. Multi-Key Environments**
  * **Task:** Support using different encryption keys for different environments (e.g., a dev key and a prod key), ensuring strict access boundaries.
  * **Test:** Attempt to decrypt a prod payload with a dev key and verify it safely rejects the operation.