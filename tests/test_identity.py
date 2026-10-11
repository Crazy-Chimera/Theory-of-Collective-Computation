import pytest

from collective_computation.identity import (
    AuthorizationError,
    AuthorizationPolicy,
    Identity,
    IdentityError,
    IdentityRegistry,
    Permission,
    SubjectType,
)


def human(identity_id: str = "human-1") -> Identity:
    return Identity(identity_id, "Researcher", SubjectType.HUMAN)


def test_identity_requires_id() -> None:
    with pytest.raises(IdentityError, match="identity_id"):
        Identity(" ", "Researcher", SubjectType.HUMAN)


def test_identity_requires_display_name() -> None:
    with pytest.raises(IdentityError, match="display_name"):
        Identity("human-1", " ", SubjectType.HUMAN)


def test_agent_requires_controller() -> None:
    with pytest.raises(IdentityError, match="controller"):
        Identity("agent-1", "Research agent", SubjectType.AGENT)


def test_registry_registers_and_retrieves_identity() -> None:
    registry = IdentityRegistry()
    identity = registry.register(human())
    assert registry.get("human-1") == identity
    assert len(registry) == 1


def test_registry_rejects_duplicate_identity() -> None:
    registry = IdentityRegistry()
    registry.register(human())
    with pytest.raises(IdentityError, match="already registered"):
        registry.register(human())


def test_registry_requires_existing_parent() -> None:
    registry = IdentityRegistry()
    agent = Identity("agent-1", "Agent", SubjectType.AGENT, "missing")
    with pytest.raises(IdentityError, match="unknown parent"):
        registry.register(agent)


def test_registry_registers_agent_under_controller() -> None:
    registry = IdentityRegistry()
    registry.register(human())
    agent = Identity("agent-1", "Agent", SubjectType.AGENT, "human-1")
    assert registry.register(agent).parent_identity_id == "human-1"


def test_policy_denies_by_default() -> None:
    policy = AuthorizationPolicy()
    assert not policy.is_allowed("agent-1", "memory-1", Permission.MEMORY_READ)


def test_policy_grant_and_revoke() -> None:
    policy = AuthorizationPolicy()
    policy.grant("agent-1", "memory-1", Permission.MEMORY_READ)
    assert policy.is_allowed("agent-1", "memory-1", Permission.MEMORY_READ)
    policy.revoke("agent-1", "memory-1", Permission.MEMORY_READ)
    assert not policy.is_allowed("agent-1", "memory-1", Permission.MEMORY_READ)


def test_policy_rejects_empty_subject_or_resource() -> None:
    policy = AuthorizationPolicy()
    with pytest.raises(AuthorizationError):
        policy.grant("", "memory-1", Permission.MEMORY_READ)
    with pytest.raises(AuthorizationError):
        policy.grant("agent-1", " ", Permission.MEMORY_READ)
