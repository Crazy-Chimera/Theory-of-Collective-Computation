import base64
import hashlib
import hmac
import json

import pytest

from collective_computation.authentication import (
    AuthenticationError, AuthenticatedActorContext, HMACTokenAuthenticator, authorize_actor,
)
from collective_computation.identity import AuthorizationPolicy, Identity, Permission, SubjectType
from collective_computation.identity_persistence import SQLiteIdentityRegistry

SECRET = b"test-only-secret-material-at-least-32-bytes"
NOW = 1_800_000_000


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_token(claims=None, *, secret=SECRET):
    data = {"sub": "human-1", "iss": "trusted-control-plane",
            "aud": "collective-computation", "iat": NOW - 5,
            "exp": NOW + 300, "jti": "token-unique-1"}
    if claims:
        data.update(claims)
    payload = b64(json.dumps(data, separators=(",", ":")).encode())
    signed = f"cc1.{payload}".encode("ascii")
    signature = b64(hmac.new(secret, signed, hashlib.sha256).digest())
    return f"cc1.{payload}.{signature}"


def authenticator(**kwargs):
    return HMACTokenAuthenticator(SECRET, expected_issuer="trusted-control-plane",
        expected_audience="collective-computation", clock=lambda: NOW, **kwargs)


def test_valid_token_returns_verified_actor_context():
    actor = authenticator().authenticate("Bearer " + make_token())
    assert actor == AuthenticatedActorContext("human-1", "trusted-control-plane",
        "collective-computation", NOW - 5, NOW + 300, "token-unique-1")


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer", "Bearer a.b.c"])
def test_missing_or_malformed_credentials_are_rejected(header):
    with pytest.raises(AuthenticationError):
        authenticator().authenticate(header)


def test_modified_payload_and_wrong_secret_are_rejected():
    parts = make_token().split(".")
    changed_payload = b64(b'{"sub":"human-2"}')
    with pytest.raises(AuthenticationError):
        authenticator().authenticate("Bearer cc1." + changed_payload + "." + parts[2])
    with pytest.raises(AuthenticationError):
        authenticator().authenticate("Bearer " + make_token(secret=b"another-test-secret-at-least-32-bytes"))


@pytest.mark.parametrize("claims", [
    {"exp": NOW}, {"iat": NOW + 1}, {"exp": NOW + 7200},
    {"iss": "untrusted"}, {"aud": "other-service"}, {"sub": ""},
])
def test_expired_future_wrong_issuer_audience_or_invalid_claims_are_rejected(claims):
    with pytest.raises(AuthenticationError):
        authenticator().authenticate("Bearer " + make_token(claims))


def test_secret_must_be_strong_and_audience_is_mandatory():
    with pytest.raises(ValueError):
        HMACTokenAuthenticator(b"short", expected_issuer="issuer", expected_audience="aud")
    with pytest.raises(ValueError):
        HMACTokenAuthenticator(SECRET, expected_issuer="issuer", expected_audience="")


def test_authorization_uses_verified_subject_and_defaults_to_deny(tmp_path):
    registry = SQLiteIdentityRegistry(tmp_path / "ids.sqlite3")
    try:
        registry.register(Identity("human-1", "Researcher", SubjectType.HUMAN))
        policy = AuthorizationPolicy()
        actor = authenticator().authenticate("Bearer " + make_token())
        with pytest.raises(AuthenticationError, match="access denied"):
            authorize_actor(actor, registry=registry, policy=policy,
                resource_id="mem-1", permission=Permission.MEMORY_READ)
        policy.grant("human-1", "mem-1", Permission.MEMORY_READ)
        authorize_actor(actor, registry=registry, policy=policy,
            resource_id="mem-1", permission=Permission.MEMORY_READ)
        policy.revoke("human-1", "mem-1", Permission.MEMORY_READ)
        with pytest.raises(AuthenticationError, match="access denied"):
            authorize_actor(actor, registry=registry, policy=policy,
                resource_id="mem-1", permission=Permission.MEMORY_READ)
    finally:
        registry.close()


def test_caller_supplied_actor_id_is_not_an_authorization_input():
    assert "actor_id" not in authorize_actor.__code__.co_varnames
