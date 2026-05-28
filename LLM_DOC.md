# Latch Clone Agent Prompt

Use this prompt in your external LLM-driven deployment agent.

---

You are orchestrating secure Latch credential migration from a source machine to a target machine (for example an LXC container) using command output forwarding.

## Goal

Recreate Latch keyring state on the target machine without exposing secrets in plaintext transport logs.

## Protocol

Optional hardening values:
- VERIFY_CODE: short one-time string shared out-of-band between source and target
- PROJECT_FILTERS: optional list of project names to export
- ENV_FILTERS: optional list of env names for env-specific keys

### Step 1: Target creates an offer

On target machine, run:

latch clone offer --ttl-minutes 10

This prints a JSON offer containing:
- offer_id
- recipient_public_key
- created_at
- expires_at

Capture this output and send it to the source machine.

### Step 2: Source creates encrypted payload

On source machine, write offer JSON to a file (for example offer.json), then run:

latch clone create --offer-file ./offer.json --stdout-file ./payload.json

This prints a JSON payload containing:
- offer_id
- ephemeral_public_key
- ciphertext

Optional source flags:
- --project <name> (repeatable)
- --env <name> (repeatable)
- --verify-code <VERIFY_CODE>

Capture this output and send it back to target.

### Step 3: Target applies payload

On target machine, write payload JSON to a file (for example payload.json), then run:

latch clone apply --payload-file ./payload.json

Or stream directly:

cat payload.json | latch clone apply --stdin

Optional target flag:
- --verify-code <VERIFY_CODE>

This restores keyring credentials and merges project metadata.

## Data migrated

The payload may include these keyring slots:
- github.pat
- github.secrets_repo
- <project>.key
- <project>.key.<env>
- <project>.pat (legacy)

And project metadata entries used by Latch in ~/.latch/config.toml.

## Automation contract

Your agent should:
1. Treat all offer/payload JSON as sensitive.
2. Never log decrypted credential values.
3. Check command exit codes and abort on non-zero.
4. Ensure Step 3 runs before offer expiration.
5. Retry by generating a new offer when expired.
6. If VERIFY_CODE is used, require it on both create and apply.

## Example machine-to-machine sequence

Target:
- run latch clone offer
- return stdout JSON as OFFER_JSON

Source:
- write OFFER_JSON to offer.json
- run latch clone create --offer-file offer.json --stdout-file payload.json [--project ...] [--env ...] [--verify-code ...]
- return stdout JSON as PAYLOAD_JSON

Target:
- write PAYLOAD_JSON to payload.json
- run latch clone apply --payload-file payload.json [--verify-code ...]
- verify by running latch status in a linked project folder

## Optional post-checks

- latch login is not required after successful clone apply.
- latch init in new folders should reuse cloned PAT/repo defaults.
- latch project should list and bind projects without re-entering credentials.
