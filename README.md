# Theory of Collective Computation

Reference implementation for identity-bound agents, authorized memory, provenance, and collective computation.

## Current milestone: Actor-attributed Authorization Audit v0.6.0

The foundation includes persistent identities and controller relationships, deny-by-default permissions, SQLite memory provenance, HMAC bearer-token verification, verified actor contexts, and authenticated grant/revoke operations whose audit events record the administrator identity.

## Security boundaries

HMACTokenAuthenticator verifies signed bearer tokens. authorize_actor checks the verified context, its expiry, registered identity, and deny-by-default policy. Token issuance must remain in a trusted control plane. Never expose the HMAC key to clients or commit it to the repository.

SQLiteAuthorizationPolicy.grant_as() and revoke_as() require a verified actor with authorization:manage on the reserved "*" resource and attribute the audit event to that actor. The legacy grant()/revoke() methods remain trusted local/bootstrap operations; their audit events have no authenticated actor attribution and must not be exposed directly to untrusted callers.

No login endpoint, token issuance endpoint, or public identity/authorization/memory HTTP API is added. The HTTP service remains health-only. Key rotation, token revocation/JTI denylist, production identity-provider integration, rate limiting, secure database operations, and independent security review remain future work.

Audit rows are append-only under SQLite triggers, but a privileged database administrator can alter the database. SQLite stores plaintext. Existing schema v1 databases are migrated to v2 with a nullable actor_id; earlier audit events remain unattributed.

The current Render free service has no persistent disk configured; no database has been connected or provisioned. Do not treat deployed Render as a durable identity/memory service.

## Development

Requires Python 3.11+.

    python -m pip install -e ".[dev]"
    python -m compileall -q src
    pytest

See docs/ITERATION-4.md, docs/ITERATION-5.md, docs/ITERATION-6.md, docs/ITERATION-7.md, and docs/ITERATION-8.md.

The Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ framework is conceptual architecture, not experimentally established physical law.
