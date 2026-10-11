# Theory of Collective Computation

A protocol and reference implementation for identity-bound agents, authorized memory, distributed computation, verified knowledge contributions, and transparent rewards.

## Current milestone: Persistent Memory & Provenance v0.3.0

The current foundation includes:
- explicit participant identities and agent registration;
- deny-by-default authorization grants;
- an in-memory reference store and a SQLite-backed persistent memory adapter;
- SHA-256 content/record hashes and parent lineage verification;
- versioned SQLite schema migration and database-level append-only triggers;
- a minimal health endpoint for Render;
- unit tests and GitHub Actions CI configuration.

SQLiteMemoryStore persists records, but identity registration and authorization grants remain caller-supplied in-memory components. Every read/write still requires explicit grants. There is no HTTP memory API and no production authentication in this milestone. Hashes are integrity checks, not signatures or proof against an administrator who can replace the database and its hashes.

A SQLite file survives process restarts only when stored on durable storage. Render's current service is on the free plan without a persistent disk configured, so this commit does not make the deployed Render service durably persistent. No database was provisioned or connected. Do not store sensitive data or expose memory operations publicly.

## Development

Requires Python 3.11+.

    python -m pip install -e ".[dev]"
    python -m compileall -q src
    pytest

Run the health service:

    python -m collective_computation.server

The service listens on 0.0.0.0:10000 by default. Configure PORT to override it. GET /health returns a small JSON health response. Memory operations remain a library interface and are not routed over HTTP.

See docs/ITERATION-4.md and docs/ITERATION-5.md.

The Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ framework is used as a conceptual architecture. Its equations are not represented here as experimentally established physical laws.
