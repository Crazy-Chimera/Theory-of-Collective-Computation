from dataclasses import replace

import pytest

from collective_computation.identity import (
    AuthorizationPolicy,
    Identity,
    IdentityRegistry,
    Permission,
    SubjectType,
)
from collective_computation.memory import (
    MemoryAccessDenied,
    MemoryConflict,
    MemoryNotFound,
    MemoryStore,
)


@pytest.fixture
def setup_store():
    identities = IdentityRegistry()
    identities.register(Identity("human-1", "Researcher", SubjectType.HUMAN))
    identities.register(Identity("agent-1", "Research Agent", SubjectType.AGENT, "human-1"))
    policy = AuthorizationPolicy()
    store = MemoryStore(identities, policy)
    return identities, policy, store


def test_create_requires_explicit_write_grant(setup_store):
    _, _, store = setup_store
    with pytest.raises(MemoryAccessDenied, match="write denied"):
        store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="fact")


def test_create_and_read_require_separate_explicit_grants(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    record = store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="fact")
    assert record.content_sha256
    with pytest.raises(MemoryAccessDenied):
        store.read(actor_id="human-1", memory_id="mem-1")
    policy.grant("human-1", "mem-1", Permission.MEMORY_READ)
    assert store.read(actor_id="human-1", memory_id="mem-1") == record


def test_unknown_actor_and_owner_are_rejected(setup_store):
    _, policy, store = setup_store
    policy.grant("intruder", "mem-1", Permission.MEMORY_WRITE)
    with pytest.raises(MemoryAccessDenied, match="not registered"):
        store.create(actor_id="intruder", memory_id="mem-1", owner_id="human-1", content="x")
    policy.grant("human-1", "mem-2", Permission.MEMORY_WRITE)
    with pytest.raises(ValueError, match="owner identity"):
        store.create(actor_id="human-1", memory_id="mem-2", owner_id="unknown", content="x")


def test_duplicate_memory_id_is_rejected(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="first")
    with pytest.raises(MemoryConflict):
        store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="second")


def test_provenance_links_parent_hash(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-parent", Permission.MEMORY_WRITE)
    policy.grant("human-1", "mem-parent", Permission.MEMORY_READ)
    policy.grant("human-1", "mem-child", Permission.MEMORY_WRITE)
    parent = store.create(actor_id="human-1", memory_id="mem-parent", owner_id="human-1", content="source", source_ref="paper:1")
    child = store.create(actor_id="human-1", memory_id="mem-child", owner_id="human-1", content="derived", parent_memory_id="mem-parent")
    assert child.parent_memory_id == parent.memory_id
    assert child.parent_record_sha256 == parent.record_sha256
    assert store.verify("mem-parent") is True
    assert store.verify("mem-child") is True


def test_parent_must_exist_and_be_readable(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "child", Permission.MEMORY_WRITE)
    with pytest.raises(MemoryNotFound):
        store.create(actor_id="human-1", memory_id="child", owner_id="human-1", content="derived", parent_memory_id="missing")
    policy.grant("human-1", "parent", Permission.MEMORY_WRITE)
    store.create(actor_id="human-1", memory_id="parent", owner_id="human-1", content="source")
    with pytest.raises(MemoryAccessDenied, match="parent"):
        store.create(actor_id="human-1", memory_id="child", owner_id="human-1", content="derived", parent_memory_id="parent")


def test_revoked_read_grant_denies_future_reads(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    policy.grant("human-1", "mem-1", Permission.MEMORY_READ)
    store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="secret")
    policy.revoke("human-1", "mem-1", Permission.MEMORY_READ)
    with pytest.raises(MemoryAccessDenied):
        store.read(actor_id="human-1", memory_id="mem-1")


def test_integrity_verification_detects_content_tampering(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    record = store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content="original")
    store._records["mem-1"] = replace(record, content="tampered")
    assert store.verify("mem-1") is False


def test_non_string_content_is_rejected(setup_store):
    _, policy, store = setup_store
    policy.grant("human-1", "mem-1", Permission.MEMORY_WRITE)
    with pytest.raises(ValueError, match="content must be a string"):
        store.create(actor_id="human-1", memory_id="mem-1", owner_id="human-1", content=123)  # type: ignore[arg-type]
