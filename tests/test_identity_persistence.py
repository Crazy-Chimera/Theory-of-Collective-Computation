import sqlite3
import pytest
from collective_computation.identity import AuthorizationError, Identity, IdentityError, Permission, SubjectType
from collective_computation.identity_persistence import SQLiteAuthorizationPolicy, SQLiteIdentityRegistry

def test_identity_and_parent_survive_restart(tmp_path):
    db=tmp_path/"ids.sqlite3"
    r=SQLiteIdentityRegistry(db)
    h=Identity("human-1","Researcher",SubjectType.HUMAN)
    a=Identity("agent-1","Agent",SubjectType.AGENT,"human-1")
    r.register(h); r.register(a); r.close()
    r=SQLiteIdentityRegistry(db)
    try:
        assert r.get("human-1")==h and r.get("agent-1")==a
        assert len(r)==2 and r.schema_version==2
    finally: r.close()

def test_unknown_parent_and_duplicate_are_rejected(tmp_path):
    r=SQLiteIdentityRegistry(tmp_path/"ids.sqlite3")
    try:
        with pytest.raises(IdentityError,match="unknown parent"):
            r.register(Identity("agent-1","Agent",SubjectType.AGENT,"missing"))
        h=Identity("human-1","Researcher",SubjectType.HUMAN); r.register(h)
        with pytest.raises(IdentityError,match="already registered"): r.register(h)
    finally: r.close()

def test_grants_survive_restart_and_default_deny(tmp_path):
    db=tmp_path/"ids.sqlite3"; p=SQLiteAuthorizationPolicy(db)
    assert not p.is_allowed("human-1","mem-1",Permission.MEMORY_READ)
    p.grant("human-1","mem-1",Permission.MEMORY_READ); p.close()
    p=SQLiteAuthorizationPolicy(db)
    try:
        assert p.is_allowed("human-1","mem-1",Permission.MEMORY_READ)
        assert not p.is_allowed("human-1","mem-2",Permission.MEMORY_READ)
    finally: p.close()

def test_revocation_survives_restart_and_audit_is_persistent(tmp_path):
    db=tmp_path/"ids.sqlite3"; p=SQLiteAuthorizationPolicy(db)
    p.grant("human-1","mem-1",Permission.MEMORY_READ)
    p.revoke("human-1","mem-1",Permission.MEMORY_READ)
    assert [e["event_type"] for e in p.audit_events()]==["grant_created","grant_revoked"]
    p.close(); p=SQLiteAuthorizationPolicy(db)
    try:
        assert not p.is_allowed("human-1","mem-1",Permission.MEMORY_READ)
        assert [e["event_type"] for e in p.audit_events()]==["grant_created","grant_revoked"]
    finally: p.close()

def test_grant_is_idempotent_and_permission_is_validated(tmp_path):
    p=SQLiteAuthorizationPolicy(tmp_path/"ids.sqlite3")
    try:
        p.grant("human-1","mem-1",Permission.MEMORY_READ)
        p.grant("human-1","mem-1",Permission.MEMORY_READ)
        assert len(p.audit_events())==1
        with pytest.raises(AuthorizationError): p.grant("human-1","mem-1","memory:read")
    finally: p.close()

def test_identity_and_audit_rows_are_immutable(tmp_path):
    db=tmp_path/"ids.sqlite3"; r=SQLiteIdentityRegistry(db)
    r.register(Identity("human-1","Researcher",SubjectType.HUMAN)); r.close()
    c=sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError,match="immutable"):
            c.execute("UPDATE identities SET display_name='changed' WHERE identity_id='human-1'")
        with pytest.raises(sqlite3.IntegrityError,match="append-only"): c.execute("DELETE FROM identity_audit")
    finally: c.close()

def test_registry_and_policy_share_database(tmp_path):
    db=tmp_path/"shared.sqlite3"; r=SQLiteIdentityRegistry(db)
    r.register(Identity("human-1","Researcher",SubjectType.HUMAN)); r.close()
    p=SQLiteAuthorizationPolicy(db)
    try:
        p.grant("human-1","mem-1",Permission.MEMORY_WRITE)
        assert p.is_allowed("human-1","mem-1",Permission.MEMORY_WRITE)
        assert any(e["event_type"]=="identity_registered" for e in p.audit_events())
    finally: p.close()


def test_authenticated_grant_and_revoke_record_actor_id(tmp_path):
    import base64, hashlib, hmac, json, time
    from collective_computation.authentication import HMACTokenAuthenticator
    secret = b"test-only-secret-material-at-least-32-bytes"
    now = int(time.time())
    def make_token(claims):
        data = {"sub": "admin-1", "iss": "trusted-control-plane", "aud": "collective-computation",
                "iat": now - 5, "exp": now + 300, "jti": "admin-token"}
        data.update(claims)
        payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()
        signed = f"cc1.{payload}".encode()
        sig = base64.urlsafe_b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).rstrip(b"=").decode()
        return f"cc1.{payload}.{sig}"
    auth = HMACTokenAuthenticator(secret, expected_issuer="trusted-control-plane",
        expected_audience="collective-computation")

    db = tmp_path / "audit.sqlite3"
    registry = SQLiteIdentityRegistry(db)
    policy = SQLiteAuthorizationPolicy(db)
    try:
        registry.register(Identity("admin-1", "Admin", SubjectType.HUMAN))
        registry.register(Identity("human-2", "Member", SubjectType.HUMAN))
        # Trusted local bootstrap grants the admin-management capability.
        policy.grant("admin-1", "*", Permission.AUTHORIZATION_MANAGE)
        actor = auth.authenticate("Bearer " + make_token({
            "sub": "admin-1", "jti": "admin-token",
        }))
        policy.grant_as(actor, registry, "human-2", "mem-1", Permission.MEMORY_READ)
        policy.revoke_as(actor, registry, "human-2", "mem-1", Permission.MEMORY_READ)
        events = [e for e in policy.audit_events() if e["event_type"] in {"grant_created", "grant_revoked"}]
        assert [e["event_type"] for e in events] == ["grant_created", "grant_revoked"]
        assert [e["actor_id"] for e in events] == ["admin-1", "admin-1"]
    finally:
        policy.close()
        registry.close()


def test_authenticated_grant_rejects_non_admin_and_forged_context(tmp_path):
    from collective_computation.authentication import AuthenticationError, AuthenticatedActorContext
    import base64, hashlib, hmac, json, time
    from collective_computation.authentication import HMACTokenAuthenticator
    secret = b"test-only-secret-material-at-least-32-bytes"
    now = int(time.time())
    def make_token(claims):
        data = {"sub": "human-1", "iss": "trusted-control-plane", "aud": "collective-computation",
                "iat": now - 5, "exp": now + 300, "jti": "member-token"}
        data.update(claims)
        payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()
        signed = f"cc1.{payload}".encode()
        sig = base64.urlsafe_b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).rstrip(b"=").decode()
        return f"cc1.{payload}.{sig}"
    auth = HMACTokenAuthenticator(secret, expected_issuer="trusted-control-plane",
        expected_audience="collective-computation")

    db = tmp_path / "audit.sqlite3"
    registry = SQLiteIdentityRegistry(db)
    policy = SQLiteAuthorizationPolicy(db)
    try:
        registry.register(Identity("human-1", "Member", SubjectType.HUMAN))
        actor = auth.authenticate("Bearer " + make_token({"sub": "human-1"}))
        with pytest.raises(AuthenticationError, match="access denied"):
            policy.grant_as(actor, registry, "human-1", "mem-1", Permission.MEMORY_READ)
        forged = AuthenticatedActorContext("human-1", "trusted-control-plane",
            "collective-computation", 1, 4_000_000_000, "forged")
        with pytest.raises(AuthenticationError, match="verified actor context"):
            policy.grant_as(forged, registry, "human-1", "mem-1", Permission.MEMORY_READ)
    finally:
        policy.close()
        registry.close()
