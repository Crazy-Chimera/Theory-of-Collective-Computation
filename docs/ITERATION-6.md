# Evolution Iteration 6 — Identity & Authorization Persistence

## Goal
Persist identity records, parent/controller relationships, authorization grants, revocations, and audit history while retaining default-deny behavior. No authentication system or public API is added.

## Implemented
- `SQLiteIdentityRegistry` persists identity registration and parent relationships.
- `SQLiteAuthorizationPolicy` persists grants/revocations and remains deny-by-default.
- Both can share a SQLite file with `SQLiteMemoryStore`.
- Identity/authorization schema versioning is independent of memory schema versioning.
- Identity rows are immutable; audit rows are append-only at SQLite trigger level.
- Audit metadata records identity registration, grant creation, and successful revocation; repeated grants are idempotent.
- Tests cover restart persistence, parent relationships, duplicate/unknown-parent rejection, grants, revocations, default-deny, audit history, and shared database use.

## Security and operational limits
- Persistence is not authentication. Caller-supplied subject IDs are not independently verified.
- There is no public identity, authorization, or memory HTTP API.
- Audit events cannot identify the authenticated operator because grant/revoke calls do not accept authenticated actor context.
- SQLite stores plaintext and can be rewritten by an administrator with database access. Triggers are guardrails, not cryptographic tamper-proofing.
- Render remains health-only and has no configured persistent disk. No external database was provisioned or connected; deployed service state is not claimed to persist across restarts.
- Login/credential validation, authenticated actor context, secure key handling, encrypted storage, backup/recovery, production database operations, and security review remain future work.

## Verification
Run `python -m compileall -q src` and `pytest`. Passing tests do not establish production security.

## Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ alignment
- Φ: explicit identity and controller relations.
- Ω: registration, grant, and revocation transitions.
- Ω²: identities, grants, and audit history survive reconnection.
- ΦΩ²: durable transition records preserve coherence.
- Γ: automated tests gate acceptance.
- Π/Ψ: permissions express capabilities over resources.
- Θ: authentication and actor-attribution limits are explicit.
- Ρ: grants bind subject, resource, and permission.
- Σ: default-deny, immutable identity rows, append-only audit history.
- ΙΩΤΑ: integrates identity/policy persistence with memory without exposing a public API.
