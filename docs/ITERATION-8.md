# Evolution Iteration 8 — Authenticated Audit Attribution

## Goal
Bind authorization changes to an authenticated administrator context and persist actor attribution with grant/revocation audit events.

## Implemented
- Added the `authorization:manage` permission.
- Migrated the identity schema to version 2 by adding nullable `actor_id` to `identity_audit`. Historical records remain valid and unattributed.
- Added `SQLiteAuthorizationPolicy.grant_as()` and `revoke_as()`.
- Both methods require a verifier-created, non-expired actor context, a registered actor identity, and the `authorization:manage` permission on the reserved `*` resource.
- Successful changes record the authenticated actor ID. Idempotent grants and no-op revocations do not create duplicate transition events.
- Added tests for actor attribution, denial of non-administrators, and rejection of forged actor contexts.

## Trust boundary and limitations
- Legacy `grant()` and `revoke()` remain trusted local/bootstrap operations. They do not authenticate the caller and their audit events have a null `actor_id`; they must not be exposed to untrusted clients.
- The initial administrator capability must be provisioned through a trusted local control plane. There is no public endpoint for this operation.
- No public HTTP API, login route, token issuance route, production secret, database service, persistent disk, or paid resource was added.
- SQLite append-only triggers are guardrails, not cryptographic tamper-proofing against a privileged database administrator. Data remains plaintext.
- No token revocation list, key rotation, production identity-provider integration, or independent security review is implemented.
- Render remains health-only. Its deployment being live does not mean the database adapters are wired into persistent production storage.

## Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ alignment
- Φ: actor-attribution schema and authorization-management permission.
- Ω: grant/revocation state transitions.
- Ω²: persistent audit records preserve actor IDs for authenticated changes.
- ΦΩ²: signed token claims are linked to an authorized transition.
- Γ: tests cover allowed and denied paths.
- Π/Ψ: capability grants define allowed actions over resources.
- Θ: legacy bootstrap and production-security limitations are explicit.
- Ρ: administrator, target identity, resource, and permission are linked in audit history.
- Σ: default-deny and append-only audit guardrails.
- ΙΩΤΑ: identity, authorization, and audit metadata compose without opening a public API.
