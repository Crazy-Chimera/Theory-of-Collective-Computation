# Project Context — Iteration 1

## Intent
Build a cooperative computational network where humans, organizations, and agents participate under explicit identities. Participants may develop their own agents, authorize access to selected memory, contribute computation or validated knowledge, and receive rewards under transparent rules.

The system must preserve participant autonomy, privacy, authorization, provenance, and the distinction between generated claims and verified results.

## Architecture (initial)
- **Identity & Authorization:** identity records, agent-to-controller relationships, and deny-by-default permission decisions.
- **Agent Development:** later module for versioned agent configurations, evaluation, and controlled updates.
- **Memory & Provenance:** later module for scoped memory access, contribution origin, and retention policies.
- **Collective Computation:** later module for task submission, dispatch, results, and resource accounting.
- **Knowledge Verification:** later module for evidence, review status, and provenance.
- **Economic Accounting:** later module for transparent contribution accounting and rewards.
- **HTTP service:** minimal health endpoint for deployment diagnostics.

## Conventions
- Python 3.11+; standard library for runtime code.
- pytest for tests; GitHub Actions for CI.
- Small modules, explicit contracts, minimal runtime dependencies.
- Deny access by default. No private memory is shared without explicit authorization.
- No production secrets in source control.
- Do not claim build, test, or deployment success unless tool results confirm it.

## Verification criteria
- Unit tests cover identity validation, registry behavior, permission grants, default denial, and revocation.
- CI runs pytest and Python compilation checks.
- Container starts and `GET /health` returns HTTP 200 with JSON.
- In-memory components are clearly labeled as prototype-only until persistence, authentication, and threat modeling are implemented.

## Current boundary
Identity records and permission grants are in-memory only. This milestone is a reference implementation, not a production identity provider or secure authorization boundary.
