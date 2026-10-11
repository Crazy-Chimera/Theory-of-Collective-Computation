import sqlite3

import pytest

from collective_computation.identity import (
    AuthorizationPolicy, Identity, IdentityRegistry, Permission, SubjectType,
)
from collective_computation.memory import MemoryAccessDenied, MemoryConflict
from collective_computation.persistence import SQLiteMemoryStore


def setup_identity_policy():
    identities = IdentityRegistry()
    identities.register(Identity("human-1", "Researcher", SubjectType.HUMAN))
    return identities, AuthorizationPolicy()


def test_record_survives_close_and_reopen(tmp_path):
    db = tmp_path / "memory.sqlite3"
    identities, policy = setup_identity_policy()
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    policy.grant("human-1", "mem-1", Permission.MEMORY_READ)
    store = SQLiteMemoryStore(identities, policy, db)
    record = store.create(
        actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="persist me"
    )
    store.close()
    reopened = SQLiteMemoryStore(identities, policy, db)
    try:
        assert reopened.read(actor_id="human-1", memory_id="mem-1") == record
        assert reopened.verify("mem-1") is True
        assert len(reopened) == 1
        assert reopened.schema_version == 1
    finally:
        reopened.close()


def test_authorization_is_still_required_after_reopen(tmp_path):
    db = tmp_path / "memory.sqlite3"
    identities, policy = setup_identity_policy()
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    policy.grant("human-1", "mem-1", Permission.MEMORY_READ)
    store = SQLiteMemoryStore(identities, policy, db)
    store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="private")
    store.close()
    policy.revoke("human-1", "mem-1", Permission.MEMORY_READ)
    reopened = SQLiteMemoryStore(identities, policy, db)
    try:
        with pytest.raises(MemoryAccessDenied):
            reopened.read(actor_id="human-1", memory_id="mem-1")
        assert reopened.verify("mem-1") is True
    finally:
        reopened.close()


def test_parent_lineage_survives_restart(tmp_path):
    db = tmp_path / "memory.sqlite3"
    identities, policy = setup_identity_policy()
    for memory_id in ("parent", "child"):
        policy.grant("human-1", memory_id, Permission.MEMORY_WRITE)
        policy.grant("human-1", memory_id, Permission.MEMORY_READ)
    store = SQLiteMemoryStore(identities, policy, db)
    parent = store.create(
        actor_id="human-1", memory_id="parent", owner_id="human-1", content="source"
    )
    child = store.create(
        actor_id="human-1", memory_id="child", owner_id="human-1",
        content="derived", parent_memory_id="parent"
    )
    store.close()
    reopened = SQLiteMemoryStore(identities, policy, db)
    try:
        assert reopened.read(actor_id="human-1", memory_id="child") == child
        assert child.parent_record_sha256 == parent.record_sha256
        assert reopened.verify("child") is True
    finally:
        reopened.close()


def test_duplicate_id_is_rejected_by_database_constraint(tmp_path):
    identities, policy = setup_identity_policy()
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    store = SQLiteMemoryStore(identities, policy, tmp_path / "memory.sqlite3")
    try:
        store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="one")
        with pytest.raises(MemoryConflict):
            store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="two")
    finally:
        store.close()


def test_schema_migration_is_idempotent(tmp_path):
    db = tmp_path / "memory.sqlite3"
    identities, policy = setup_identity_policy()
    first = SQLiteMemoryStore(identities, policy, db)
    assert first.schema_version == 1
    first.close()
    second = SQLiteMemoryStore(identities, policy, db)
    try:
        assert second.schema_version == 1
        assert len(second) == 0
    finally:
        second.close()


def test_database_rejects_record_mutation_and_deletion(tmp_path):
    db = tmp_path / "memory.sqlite3"
    identities, policy = setup_identity_policy()
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    store = SQLiteMemoryStore(identities, policy, db)
    store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="immutable")
    store.close()
    connection = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE memory_records SET content = 'tampered' WHERE memory_id = 'mem-1'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM memory_records WHERE memory_id = 'mem-1'")
    finally:
        connection.close()
