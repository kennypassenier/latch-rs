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

On source machine, run directly from target offer (no temp file needed):

latch clone create --offer-stdin [--project ...] [--env ...] [--verify-code ...]

Or from a file:

latch clone create --offer-file ./offer.json

This prints a JSON payload containing:
- offer_id
- ephemeral_public_key
- ciphertext
- optional integrity_tag

Optional source flags:
- --offer-stdin (read offer from stdin; default if no --offer/--offer-file)
- --project <name> (repeatable; filter which projects to export)
- --env <name> (repeatable; filter which env-specific keys to export)
- --verify-code <VERIFY_CODE> (add integrity tag to payload)
- --stdout-file <path> (write payload to file in addition to stdout)

Capture this output and send it back to target.

### Step 3: Target applies payload

On target machine, read directly from source (no temp file needed):

latch clone apply --stdin [--verify-code ...]

Or from a file:

latch clone apply --payload-file ./payload.json

Optional target flags:
- --stdin (read payload from stdin; default if no --payload/--payload-file)
- --verify-code <VERIFY_CODE> (verify payload integrity before decrypting)

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

### Piped (zero temp files):

```bash
# On target, pipe offer directly to source over SSH, get payload back, apply immediately
latch clone offer | ssh source-user@source-host \
  'latch clone create --offer-stdin --verify-code shared-secret' | \
  latch clone apply --stdin --verify-code shared-secret
```

### With verification:

```bash
# Same flow but with one-time code for transport integrity
CODE=$(openssl rand -hex 8)
latch clone offer | ssh source-user@source-host \
  "latch clone create --offer-stdin --verify-code $CODE" | \
  latch clone apply --stdin --verify-code $CODE
```

### Step-by-step (with temp files if needed):

1. Target: `latch clone offer` → save to offer.json, send to source
2. Source: `latch clone create --offer-file offer.json` → save output to payload.json, send to target
3. Target: `latch clone apply --payload-file payload.json` → restores keyring
4. Verify: `latch status` in a linked project folder

## Optional post-checks

- latch login is not required after successful clone apply.
- latch init in new folders should reuse cloned PAT/repo defaults.
- latch project should list and bind projects without re-entering credentials.
