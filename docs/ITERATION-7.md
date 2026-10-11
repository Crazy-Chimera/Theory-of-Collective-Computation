# Evolution Iteration 7 — Authenticated Access & Trust Boundary

## Goal
Introduce a verifiable actor context and request-level authorization helper without adding a public HTTP API or enabling authentication on the deployed service.

## Implemented
- HMACTokenAuthenticator verifies compact cc1 bearer tokens using HMAC-SHA256.
- Requires a server-side secret of at least 32 bytes, configured issuer and audience, subject and token ID, integer issue/expiry claims, and a bounded token lifetime.
- Rejects malformed tokens, duplicate JSON claims, signature mismatch, wrong issuer/audience, future issue times, expired tokens, and excessive lifetimes.
- Uses constant-time signature comparison and limits token size.
- AuthenticatedActorContext carries the subject derived from the verified token.
- authorize_actor accepts the context rather than a client-supplied actor ID, requires the identity to exist, and applies the existing deny-by-default policy.
- Tests cover token verification, tampering, invalid credentials, claim validation, authorization, and revocation.

## Trust boundary and limitations
- No HTTP route, login endpoint, token issuance endpoint, or session store was added. The Render service remains health-only.
- Token issuance must happen only in a trusted control plane. The HMAC signing key must never be shipped to clients, committed to source control, logged, or exposed in environment output.
- This is a minimal library-level verifier, not a complete production identity provider. There is no key rotation, token revocation/JTI denylist, refresh flow, rate limiting, encrypted database, or independent security audit.
- The actor context is a process-local value. Never deserialize it directly from client JSON; create it only from HMACTokenAuthenticator.authenticate().
- Identity/policy changes and audit attribution are not yet bound to authenticated administrator roles. Grant/revoke operations remain privileged control-plane actions.
- No production secret, external database, persistent disk, or paid resource was provisioned.
- A successful test suite is not proof of production security.

## Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ alignment
- Φ: explicit token and actor-context contract.
- Ω: issue/expiry validity and authorization decisions.
- Ω²: token ID supports later audit/revocation integration, but no denylist is implemented yet.
- ΦΩ²: signed claims bind the subject, issuer, audience, and validity window.
- Γ: adversarial and positive tests gate acceptance.
- Π/Ψ: permission checks govern access to a resource.
- Θ: the trust boundary and remaining gaps are documented.
- Ρ: the verified subject is related to a registered identity and resource.
- Σ: signature verification, audience binding, size limits, and default-deny.
- ΙΩΤΑ: authentication and authorization are composable as a library boundary without exposing memory publicly.
