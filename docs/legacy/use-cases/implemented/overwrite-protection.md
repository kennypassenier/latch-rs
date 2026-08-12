# Overwrite Protection

**Status:** Implemented  
**Category:** UX / Safety

## Summary

Before `latch pull` overwrites a local `.env` file, check whether the existing local content differs from the remote version. If it does, prompt the user for confirmation.

## User Story

As a developer who has made local changes to `.env` that I haven't saved yet, I want Latch to warn me before overwriting my local file so I don't accidentally lose work.

## Acceptance Criteria

- On `latch pull`, if a local `.env` exists and its bytes differ from the decrypted remote content, print a notice and prompt: `"Overwrite <path>? [y/N]"`.
- Default answer is **No** (skip, don't overwrite).
- If user confirms, file is overwritten.
- If user declines or presses Enter, file is skipped.
- Count of skipped files is reported at the end.
- `--dry-run` mode shows what would be overwritten without prompting.

## Implementation Notes

- Implemented in `src/commands/pull.rs` using `dialoguer::Confirm`.
