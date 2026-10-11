"""Access-controlled, append-only reference memory with provenance hashes.

The store is in-memory and intended for a prototype. Hashes detect accidental
or unauthorized mutation only when compared against a trusted record; they do
not provide signatures, durable audit storage, or a complete security boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .identity import AuthorizationPolicy, IdentityRegistry, Permission


class MemoryError(ValueError):
    """Base error for memory and provenance operations."""


class MemoryAccessDenied(MemoryError):
    """Raised when a subject lacks an explicit memory permission."""


class MemoryConflict(MemoryError):
    """Raised when a memory ID already exists."""


class MemoryNotFound(MemoryError):
    """Raised when a referenced memory record does not exist."""


class MemoryIntegrityError(MemoryError):
    """Raised when a memory record's provenance cannot be verified."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    memory_id: str
    owner_id: str
    created_by: str
    content: str
    content_sha256: str
    created_at: str
    parent_memory_id: str | None
    parent_record_sha256: str | None
    source_ref: str | None
    record_sha256: str


class MemoryStore:
    """In-memory append-only memory; all access requires explicit grants.

    Authorization resource IDs are the exact `memory_id` values. A creator
    does not automatically receive read access, and an owner does not bypass
    policy. Grant MEMORY_WRITE before creating and MEMORY_READ before reading.
    """

    def __init__(
        self, identities: IdentityRegistry, authorization: AuthorizationPolicy
    ) -> None:
        self._identities = identities
        self._authorization = authorization
        self._records: dict[str, MemoryRecord] = {}

    @staticmethod
    def _record_payload(
        *, memory_id: str, owner_id: str, created_by: str, content_sha256: str,
        created_at: str, parent_memory_id: str | None,
        parent_record_sha256: str | None, source_ref: str | None,
    ) -> dict[str, object]:
        return {
            "memory_id": memory_id,
            "owner_id": owner_id,
            "created_by": created_by,
            "content_sha256": content_sha256,
            "created_at": created_at,
            "parent_memory_id": parent_memory_id,
            "parent_record_sha256": parent_record_sha256,
            "source_ref": source_ref,
        }

    def create(
        self,
        *,
        actor_id: str,
        memory_id: str,
        owner_id: str,
        content: str,
        parent_memory_id: str | None = None,
        source_ref: str | None = None,
    ) -> MemoryRecord:
        if not memory_id.strip() or not owner_id.strip() or not actor_id.strip():
            raise MemoryError("actor_id, memory_id, and owner_id must not be empty")
        if not isinstance(content, str):
            raise MemoryError("content must be a string")
        if source_ref is not None and not source_ref.strip():
            raise MemoryError("source_ref must be omitted or non-empty")
        if memory_id in self._records:
            raise MemoryConflict(f"memory already exists: {memory_id}")
        if self._identities.get(actor_id) is None:
            raise MemoryAccessDenied("actor identity is not registered")
        if self._identities.get(owner_id) is None:
            raise MemoryError("owner identity is not registered")
        if not self._authorization.is_allowed(actor_id, memory_id, Permission.MEMORY_WRITE):
            raise MemoryAccessDenied(f"write denied for memory: {memory_id}")

        parent_hash = None
        if parent_memory_id is not None:
            parent = self._records.get(parent_memory_id)
            if parent is None:
                raise MemoryNotFound(f"parent memory not found: {parent_memory_id}")
            if not self._authorization.is_allowed(
                actor_id, parent_memory_id, Permission.MEMORY_READ
            ):
                raise MemoryAccessDenied(f"read denied for parent memory: {parent_memory_id}")
            if not self.verify(parent_memory_id):
                raise MemoryIntegrityError(f"parent memory failed verification: {parent_memory_id}")
            parent_hash = parent.record_sha256

        created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        content_hash = _sha256(content.encode("utf-8"))
        payload = self._record_payload(
            memory_id=memory_id,
            owner_id=owner_id,
            created_by=actor_id,
            content_sha256=content_hash,
            created_at=created_at,
            parent_memory_id=parent_memory_id,
            parent_record_sha256=parent_hash,
            source_ref=source_ref,
        )
        record_hash = _sha256(_canonical_json(payload))
        record = MemoryRecord(
            memory_id=memory_id,
            owner_id=owner_id,
            created_by=actor_id,
            content=content,
            content_sha256=content_hash,
            created_at=created_at,
            parent_memory_id=parent_memory_id,
            parent_record_sha256=parent_hash,
            source_ref=source_ref,
            record_sha256=record_hash,
        )
        self._records[memory_id] = record
        return record

    def read(self, *, actor_id: str, memory_id: str) -> MemoryRecord:
        record = self._records.get(memory_id)
        if record is None:
            raise MemoryNotFound(f"memory not found: {memory_id}")
        if not self._authorization.is_allowed(actor_id, memory_id, Permission.MEMORY_READ):
            raise MemoryAccessDenied(f"read denied for memory: {memory_id}")
        return record

    def verify(self, memory_id: str) -> bool:
        """Verify content hash, record hash, and parent lineage without returning content."""
        record = self._records.get(memory_id)
        if record is None:
            raise MemoryNotFound(f"memory not found: {memory_id}")
        if _sha256(record.content.encode("utf-8")) != record.content_sha256:
            return False
        expected_payload = self._record_payload(
            memory_id=record.memory_id,
            owner_id=record.owner_id,
            created_by=record.created_by,
            content_sha256=record.content_sha256,
            created_at=record.created_at,
            parent_memory_id=record.parent_memory_id,
            parent_record_sha256=record.parent_record_sha256,
            source_ref=record.source_ref,
        )
        if _sha256(_canonical_json(expected_payload)) != record.record_sha256:
            return False
        if record.parent_memory_id is None:
            return record.parent_record_sha256 is None
        parent = self._records.get(record.parent_memory_id)
        return (
            parent is not None
            and parent.record_sha256 == record.parent_record_sha256
            and self.verify(parent.memory_id)
        )

    def __len__(self) -> int:
        return len(self._records)
