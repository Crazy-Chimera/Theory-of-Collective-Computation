# Theory of Collective Computation

Reference implementation for identity-bound agents, authorized memory, provenance, and collective computation.

## Current milestone: Authenticated Access Boundary v0.5.0

The foundation includes persistent identity registration and parent/controller relations, persistent deny-by-default grants and revocations, append-only audit metadata, SQLite memory storage with provenance hashes, and a library-level HMAC bearer-token verifier that creates a verified actor context.

## Security boundaries

HMACTokenAuthenticator validates signed bearer tokens and authorize_actor applies registered-identity and deny-by-default policy checks. Token issuance must remain in a trusted control plane. Never expose the HMAC key to clients or commit it to the repository.

This milestone adds no login endpoint, token issuance endpoint, or public identity/authorization/memory HTTP API. The HTTP service remains health-only. The actor context must be produced by the authenticator, not deserialized from request data. Key rotation, token revocation, production identity-provider integration, rate limiting, secure database operations, and independent security review remain future work.

Audit events cannot yet identify the authenticated operator because grant/revoke calls do not accept actor context. Hashes are not signatures or protection against a privileged database administrator. SQLite stores plaintext.

The current Render free service has no persistent disk configured; no database has been connected or provisioned. Do not treat deployed Render as a durable identity/memory service.

## Development

Requires Python 3.11+.

    python -m pip install -e ".[dev]"
    python -m compileall -q src
    pytest

See docs/ITERATION-4.md, docs/ITERATION-5.md, docs/ITERATION-6.md, and docs/ITERATION-7.md.

The Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ framework is conceptual architecture, not experimentally established physical law.
