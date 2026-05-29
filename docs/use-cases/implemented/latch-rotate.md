# latch rotate

**Status:** Implemented  
**Category:** Security

## Summary

Re-encrypt all secrets for a project with a new encryption key. Downloads every secret, decrypts with the current key, re-encrypts with the new key, and pushes back to remote.

## User Story

As a security administrator, I want to rotate the encryption key after a potential credential leak so that secrets remain protected even if the old key was compromised.

## Acceptance Criteria

- Downloads and decrypts every file in the manifest using the current key.
- Prompts for a new key (generate / passphrase / paste).
- Re-encrypts all files with the new key and pushes them.
- Updates the OS keyring with the new key.
- Prints the new key for distribution to teammates.
- Old key can no longer decrypt any file after rotation completes.

## Command

```bash
latch rotate
```

## Post-Rotation Steps

1. Share the new key with all team members via a secure channel.
2. Update `LATCH_KEY` in all CI/CD environments.
3. Each team member re-runs `latch pull` to get the re-encrypted files.

## Implementation Notes

- `src/commands/rotate.rs`.
