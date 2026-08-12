# Machine-to-Machine Credential Clone

**Status:** Implemented  
**Category:** Operations / Security

## Summary

Securely transfer Latch keyring state (PAT, secrets repo, project keys) from one machine to another using an ephemeral end-to-end encrypted payload. No secrets are exposed in logs or temp files.

## User Story

As a developer setting up a new machine or deploying Latch to an LXC container, I want to transfer my full Latch credential set without manually copying secrets over SSH or chat.

## Acceptance Criteria

- `latch clone offer` on the target generates an ephemeral x25519 public key and an expiring offer (default 10 minutes).
- `latch clone create` on the source encrypts the local keyring state to the target's public key.
- `latch clone apply` on the target decrypts and restores keyring entries.
- Payload is encrypted end-to-end; no plaintext is transmitted.
- Optional `--verify-code` adds an integrity tag for transport assurance.
- Offer expires automatically; applying an expired offer is rejected.
- Works fully pipelined (zero temp files) via stdin/stdout.

## Commands

```bash
# Target generates offer
latch clone offer [--ttl-minutes 10]

# Source creates encrypted payload
latch clone create --offer-stdin [--project ...] [--env ...]

# Target applies payload
latch clone apply --stdin [--verify-code ...]

# One-liner (piped over SSH)
latch clone offer | ssh user@source latch clone create --offer-stdin | latch clone apply --stdin
```

## Data Migrated

- `github.pat`
- `github.secrets_repo`
- `<project>.key` and `<project>.key.<env>`
- Project metadata in `~/.latch/config.toml`

## Implementation Notes

- `src/commands/clone.rs`.
- Uses x25519 ephemeral DH for key exchange.
