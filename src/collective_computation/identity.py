"""Minimal identity and deny-by-default authorization contracts.

This module is an in-memory reference implementation. It is not a replacement
for production authentication, durable storage, or a security review.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IdentityError(ValueError):
    """Raised when an identity violates the module's contract."""


class AuthorizationError(ValueError):
    """Raised when an authorization grant is malformed."""


class SubjectType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    ORGANIZATION = "organization"


class Permission(StrEnum):
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    COMPUTE_SUBMIT = "compute:submit"
    COMPUTE_CONTRIBUTE = "compute:contribute"
    KNOWLEDGE_PUBLISH = "knowledge:publish"
    REWARD_RECEIVE = "reward:receive"


@dataclass(frozen=True, slots=True)
class Identity:
    identity_id: str
    display_name: str
    subject_type: SubjectType
    parent_identity_id: str | None = None

    def __post_init__(self) -> None:
        if not self.identity_id.strip():
            raise IdentityError("identity_id must not be empty")
        if not self.display_name.strip():
            raise IdentityError("display_name must not be empty")
        if not isinstance(self.subject_type, SubjectType):
            raise IdentityError("subject_type must be a SubjectType")
        if self.parent_identity_id == self.identity_id:
            raise IdentityError("an identity cannot be its own parent")
        if self.subject_type is SubjectType.AGENT and not self.parent_identity_id:
            raise IdentityError("an agent identity requires a controller identity")


class IdentityRegistry:
    """Small in-memory registry with explicit parent relationships."""

    def __init__(self) -> None:
        self._identities: dict[str, Identity] = {}

    def register(self, identity: Identity) -> Identity:
        if identity.identity_id in self._identities:
            raise IdentityError(f"identity already registered: {identity.identity_id}")
        parent_id = identity.parent_identity_id
        if parent_id is not None and parent_id not in self._identities:
            raise IdentityError(f"unknown parent identity: {parent_id}")
        self._identities[identity.identity_id] = identity
        return identity

    def get(self, identity_id: str) -> Identity | None:
        return self._identities.get(identity_id)

    def __len__(self) -> int:
        return len(self._identities)


class AuthorizationPolicy:
    """Explicit grant list; any ungranted request is denied."""

    def __init__(self) -> None:
        self._grants: set[tuple[str, str, Permission]] = set()

    def grant(self, subject_id: str, resource_id: str, permission: Permission) -> None:
        if not subject_id.strip() or not resource_id.strip():
            raise AuthorizationError("subject_id and resource_id must not be empty")
        if not isinstance(permission, Permission):
            raise AuthorizationError("permission must be a Permission")
        self._grants.add((subject_id, resource_id, permission))

    def revoke(self, subject_id: str, resource_id: str, permission: Permission) -> None:
        self._grants.discard((subject_id, resource_id, permission))

    def is_allowed(
        self, subject_id: str, resource_id: str, permission: Permission
    ) -> bool:
        return (subject_id, resource_id, permission) in self._grants
