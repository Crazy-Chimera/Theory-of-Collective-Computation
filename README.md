# Theory of Collective Computation

Reference implementation for identity-bound agents, authorized memory, provenance, and collective computation.

## Current milestone: Identity & Authorization Persistence v0.4.0

The foundation includes persistent identity registration and parent/controller relations, persistent deny-by-default grants and revocations, append-only audit metadata, and SQLite memory storage with provenance hashes.

Use `SQLiteIdentityRegistry`, `SQLiteAuthorizationPolicy`, and `SQLiteMemoryStore` with the same SQLite database path to persist identities, grants, and memory records together.

## Security boundaries

These are persistence components, not production authentication. The APIs trust caller-supplied identity IDs. There is no verified login, credential/token validation, session management, or public identity/authorization/memory HTTP API. Do not expose these methods through a public endpoint until authentication, request-level authorization, abuse controls, and security review are implemented.

Audit events cannot identify the authenticated operator because grant/revoke calls have no actor context. Hashes are not signatures or protection against a privileged database administrator. SQLite stores plaintext.

A SQLite file survives restarts only on durable storage. The current Render free service has no persistent disk configured; no database has been connected or provisioned for this service. Do not treat deployed Render as a durable identity/memory service.

## Development

Requires Python 3.11+.

    python -m pip install -e ".[dev]"
    python -m compileall -q src
    pytest

The HTTP service is health-only; no identity, grant, or memory operation is routed over HTTP.

See docs/ITERATION-4.md, docs/ITERATION-5.md, and docs/ITERATION-6.md.

The Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ framework is conceptual architecture, not experimentally established physical law.
