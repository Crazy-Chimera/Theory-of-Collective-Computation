# Evolution Iteration 4 — Memory & Provenance Integration

## Goal
Connect the existing identity registry and deny-by-default authorization policy to a first memory/provenance component without adding an external API or persistent database yet.

## Contract
- Every memory record has a unique `memory_id`, an existing owner identity, and an existing creator identity.
- `MEMORY_WRITE` must be explicitly granted to the creator for the exact `memory_id` before creation.
- `MEMORY_READ` must be explicitly granted for the exact `memory_id` before reading. Ownership and authorship do not bypass authorization.
- Records are immutable dataclasses and the store exposes no update/delete operation.
- Content is hashed with SHA-256. A canonical JSON record hash covers the record metadata and content hash.
- Optional parent links require the parent to exist, pass integrity verification, and be readable by the creating actor. The child stores the parent's record hash.
- Revocation is checked at read time and therefore applies to subsequent reads.

## Current limits
The store and identity/policy registries are process-local and in-memory. Hashes provide integrity comparison, not identity signatures or proof against a privileged actor who can rewrite the whole store. There is no HTTP memory API, database persistence, key management, or production authentication in this iteration.

## Verification
`tests/test_memory.py` covers explicit grants, identity checks, duplicate IDs, parent provenance, read revocation, and content-tamper detection. Run `python -m compileall -q src` and `pytest` in CI. Render's existing deployment remains the health service; this iteration does not expose memory operations over HTTP.

## Φ–Ω–Ω² alignment
- Φ: typed identity, resource and ownership relations.
- Ω: authorized creation of new records.
- Ω²: stored content, timestamp, creator, source reference and parent lineage.
- ΦΩ²: canonical content and record hashes make the memory relation checkable.
- Γ: tests verify authorization and provenance invariants before accepting this iteration.
- Σ: deny-by-default and no implicit owner bypass remain invariants.
