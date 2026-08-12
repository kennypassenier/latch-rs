# Usecase Strategy

This document defines how use cases move through the lifecycle and where they should be documented.

## Folder Intent

- `docs/usecases/planned/`: ideas worth keeping, but not approved for active implementation.
- `docs/usecases/need-clarification/`: ideas that require more information or discussion before approval.
- `docs/usecases/pending/`: approved and implementation-tracked next items.
- `docs/usecases/implemented/`: shipped behavior with references and outcomes.
- `docs/usecases/rejected/`: intentionally not implemented ideas, with rationale preserved.

## Promotion Flow

1. `planned` -> concept validated and scoped
2. `pending` -> approved for implementation and actively tracked
3. `implemented` -> shipped and documented with behavior and file references
4. `rejected` -> intentionally not implemented, rationale kept for future reassessment

## Authoring Rules

- Keep entries short and concrete.
- Prefer one feature per file.
- Include tier and status at the top.
- Record why a feature is useful, not only what it does.

## Reassessment Rule

Rejected ideas can be revived when assumptions change (new constraints, new dependencies, new operational pain). If revived, move the file back to `planned` with a short note explaining what changed.
