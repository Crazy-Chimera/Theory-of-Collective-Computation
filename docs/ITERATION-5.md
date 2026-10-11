# Evolution Iteration 5 — Persistent Memory & Provenance

## Goal

Move the Iteration 4 memory contract from process-local RAM to a versioned persistent database adapter, without adding an unauthenticated HTTP API or changing the authorization contract.

## Implemented

- SQLiteMemoryStore implements the existing MemoryStore contract using Python's standard-library SQLite driver.
- Records, content hashes, record hashes, source references, and parent links survive closing and reopening the store.
- Migration version 1 creates the record table, parent index, and append-only database triggers.
- Database constraints enforce unique memory IDs, unique record hashes, parent foreign keys, and consistent parent/hash nullability.
- The existing explicit MEMORY_WRITE and MEMORY_READ checks remain in MemoryStore; owner/creator status is not an authorization bypass.
- Tests cover restart persistence, read revocation after reopen, parent lineage, duplicate IDs, migration idempotency, and SQL-level update/delete rejection.

## Storage and security boundaries

- IdentityRegistry and AuthorizationPolicy remain caller-supplied and in-memory. Reconstructing the application requires re-registering identities and reloading grants from a trusted source.
- SQLite database records are stored as plaintext. Hashes are not signatures, encryption, external anchoring, or protection against a privileged database administrator who can replace both content and hashes.
- The library does not expose memory operations through HTTP. The public service remains a health-only endpoint.
- A local SQLite file is durable across process restarts only if the path is on durable storage. The current Render free web service has no persistent disk configured; this iteration does not claim persistent storage on Render and does not provision an external database.
- Production authentication, persistent identity/grant management, key management, backups, concurrency/load testing, and PostgreSQL integration remain future work.

## Verification contract

Run:

    python -m compileall -q src
    pytest

Passing local or CI tests establish implementation behavior in that test environment only; they do not establish production security or persistence on Render.

## Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ alignment

- Φ: typed record and parent-child relations.
- Ω: authorized creation flow.
- Ω²: durable record and provenance history.
- ΦΩ²: recomputed content and record hashes plus parent lineage checks.
- Γ: tests and schema constraints gate acceptance.
- Π/Ψ: the record carries source reference and content for later interpretation/expression.
- Θ: explicit limits and failure boundaries are documented.
- Ρ: authorization remains contextual and explicit.
- Σ: append-only and default-deny remain invariants.
- ΙΩΤΑ: integration with the existing memory contract without exposing a new public API.
