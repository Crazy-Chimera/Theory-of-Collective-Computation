"""Verified actor context from HMAC-authenticated bearer tokens.

This module deliberately provides a verifier and an authorization boundary only.
Token issuance belongs in a trusted control plane; never give the signing key to
untrusted clients. No HTTP route is added by this module.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .identity import Permission

_CONTEXT_MARKER = object()


class AuthenticationError(ValueError):
    """Raised when a bearer token is missing, malformed, or invalid."""


class IdentityLookup(Protocol):
    def get(self, identity_id: str): ...


class PolicyCheck(Protocol):
    def is_allowed(self, subject_id: str, resource_id: str, permission: Permission) -> bool: ...


@dataclass(frozen=True, slots=True)
class AuthenticatedActorContext:
    """Identity claims produced by a successful local token verification."""
    subject_id: str
    issuer: str
    audience: str
    issued_at: int
    expires_at: int
    token_id: str
    _verification_marker: object = field(default=None, repr=False, compare=False)


def _b64url_decode(value: str) -> bytes:
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not value or any(c not in allowed for c in value):
        raise AuthenticationError("malformed bearer token")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AuthenticationError("malformed bearer token") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationError("duplicate token claim")
        result[key] = value
    return result


class HMACTokenAuthenticator:
    """Verify compact cc1 bearer tokens signed with HMAC-SHA256.

    The HMAC-SHA256 key must be a server-side secret of at least 32 bytes.
    Required claims: string sub, iss, aud, jti and integer iat, exp.
    Expiry is exclusive: exp <= now is denied.
    """
    _PREFIX = "cc1"
    _MAX_TOKEN_LENGTH = 8192
    _REQUIRED = {"sub", "iss", "aud", "jti", "iat", "exp"}

    def __init__(
        self,
        secret: bytes | str,
        *,
        expected_issuer: str,
        expected_audience: str,
        max_lifetime_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("HMAC secret must contain at least 32 bytes")
        if not expected_issuer or not expected_audience:
            raise ValueError("expected issuer and audience are required")
        if type(max_lifetime_seconds) is not int or max_lifetime_seconds <= 0:
            raise ValueError("max_lifetime_seconds must be a positive integer")
        self._secret = secret
        self._issuer = expected_issuer
        self._audience = expected_audience
        self._max_lifetime = max_lifetime_seconds
        self._clock = clock

    def authenticate(self, authorization_header: str | None) -> AuthenticatedActorContext:
        """Verify an Authorization header and return its trusted actor context."""
        if not isinstance(authorization_header, str):
            raise AuthenticationError("bearer credentials required")
        scheme, separator, token = authorization_header.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or " " in token:
            raise AuthenticationError("bearer credentials required")
        if len(token) > self._MAX_TOKEN_LENGTH:
            raise AuthenticationError("malformed bearer token")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != self._PREFIX:
            raise AuthenticationError("malformed bearer token")

        try:
            signed = f"{parts[0]}.{parts[1]}".encode("ascii")
        except UnicodeEncodeError as exc:
            raise AuthenticationError("malformed bearer token") from exc
        supplied_signature = _b64url_decode(parts[2])
        expected_signature = hmac.new(self._secret, signed, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise AuthenticationError("invalid bearer token")
        try:
            payload = _b64url_decode(parts[1])
            claims = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except AuthenticationError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise AuthenticationError("malformed bearer token") from exc
        if not isinstance(claims, dict) or not self._REQUIRED.issubset(claims):
            raise AuthenticationError("required token claims missing")
        for name in ("sub", "iss", "aud", "jti"):
            if not isinstance(claims[name], str) or not claims[name].strip():
                raise AuthenticationError("invalid token claim")
        for name in ("iat", "exp"):
            if type(claims[name]) is not int or claims[name] < 0:
                raise AuthenticationError("invalid token claim")
        if claims["iss"] != self._issuer or claims["aud"] != self._audience:
            raise AuthenticationError("token issuer or audience mismatch")

        now = int(self._clock())
        issued_at, expires_at = claims["iat"], claims["exp"]
        if issued_at > now or expires_at <= now or expires_at <= issued_at:
            raise AuthenticationError("token is not currently valid")
        if expires_at - issued_at > self._max_lifetime:
            raise AuthenticationError("token lifetime exceeds policy")
        return AuthenticatedActorContext(
            subject_id=claims["sub"], issuer=claims["iss"], audience=claims["aud"],
            issued_at=issued_at, expires_at=expires_at, token_id=claims["jti"],
            _verification_marker=_CONTEXT_MARKER,
        )


def authorize_actor(
    actor: AuthenticatedActorContext,
    *,
    registry: IdentityLookup,
    policy: PolicyCheck,
    resource_id: str,
    permission: Permission,
) -> None:
    """Enforce identity existence and default-deny policy for a verified actor.

    The subject comes from the verified context; no actor_id argument exists.
    """
    if not isinstance(actor, AuthenticatedActorContext) or actor._verification_marker is not _CONTEXT_MARKER:
        raise AuthenticationError("verified actor context required")
    if registry.get(actor.subject_id) is None:
        raise AuthenticationError("authenticated identity is not registered")
    if not policy.is_allowed(actor.subject_id, resource_id, permission):
        raise AuthenticationError("access denied")
