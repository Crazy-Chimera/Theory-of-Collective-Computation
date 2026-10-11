"""SQLite-backed persistent memory adapter with append-only record storage.

This adapter persists memory records and provenance. IdentityRegistry and
AuthorizationPolicy remain caller-supplied and are not persisted by this module.
A file-backed database is durable only when its filesystem is durable.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from threading import RLock

from .memory import MemoryConflict, MemoryRecord, MemoryStore

_SCHEMA_VERSION = 1


class _SQLiteRecordMap(MutableMapping[str, MemoryRecord]):
    """Mapping adapter that preserves the existing MemoryStore contract."""

    def __init__(self, connection: sqlite3.Connection, lock: RLock) -> None:
        self._connection = connection
        self._lock = lock

    @staticmethod
    def _from_row(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            memory_id=row["memory_id"], owner_id=row["owner_id"],
            created_by=row["created_by"], content=row["content"],
            content_sha256=row["content_sha256"], created_at=row["created_at"],
            parent_memory_id=row["parent_memory_id"],
            parent_record_sha256=row["parent_record_sha256"],
            source_ref=row["source_ref"], record_sha256=row["record_sha256"],
        )

    def __getitem__(self, key: str) -> MemoryRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM memory_records WHERE memory_id = ?", (key,)
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return self._from_row(row)

    def __setitem__(self, key: str, record: MemoryRecord) -> None:
        if key != record.memory_id:
            raise ValueError("mapping key must match record.memory_id")
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """INSERT INTO memory_records (
                        memory_id, owner_id, created_by, content, content_sha256,
                        created_at, parent_memory_id, parent_record_sha256,
                        source_ref, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (record.memory_id, record.owner_id, record.created_by,
                     record.content, record.content_sha256, record.created_at,
                     record.parent_memory_id, record.parent_record_sha256,
                     record.source_ref, record.record_sha256),
                )
        except sqlite3.IntegrityError as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise MemoryConflict(
                    f"memory already exists: {record.memory_id}"
                ) from exc
            raise

    def __delitem__(self, key: str) -> None:
        raise TypeError("persistent memory is append-only; deletion is unsupported")

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT memory_id FROM memory_records ORDER BY created_at, memory_id"
            ).fetchall()
        return iter(row["memory_id"] for row in rows)

    def __len__(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM memory_records"
            ).fetchone()
        return int(row["count"])


class SQLiteMemoryStore(MemoryStore):
    """Persistent SQLite store retaining explicit authorization checks.

    Use a file path for persistence. The special path ':memory:' is suitable
    only for isolated tests and does not survive connection closure.
    Identities and authorization grants are not persisted by this class.
    """

    def __init__(self, identities, authorization, database_path: str | Path) -> None:
        super().__init__(identities, authorization)
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        self._lock = RLock()
        self._connection = sqlite3.connect(
            self.database_path, timeout=5.0, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._migrate()
        self._records = _SQLiteRecordMap(self._connection, self._lock)

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            row = self._connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
            current_version = row["version"] or 0
            if current_version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {current_version} is newer than supported "
                    f"schema {_SCHEMA_VERSION}"
                )
            if current_version < 1:
                self._connection.execute(
                    """CREATE TABLE memory_records (
                        memory_id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        content TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        parent_memory_id TEXT REFERENCES memory_records(memory_id),
                        parent_record_sha256 TEXT,
                        source_ref TEXT,
                        record_sha256 TEXT NOT NULL UNIQUE,
                        CHECK (
                            (parent_memory_id IS NULL AND parent_record_sha256 IS NULL)
                            OR
                            (parent_memory_id IS NOT NULL AND parent_record_sha256 IS NOT NULL)
                        )
                    )"""
                )
                self._connection.execute(
                    "CREATE INDEX memory_records_parent_idx "
                    "ON memory_records(parent_memory_id)"
                )
                self._connection.execute(
                    """CREATE TRIGGER memory_records_no_update
                    BEFORE UPDATE ON memory_records BEGIN
                        SELECT RAISE(ABORT, 'memory records are append-only');
                    END"""
                )
                self._connection.execute(
                    """CREATE TRIGGER memory_records_no_delete
                    BEFORE DELETE ON memory_records BEGIN
                        SELECT RAISE(ABORT, 'memory records are append-only');
                    END"""
                )
                self._connection.execute(
                    "INSERT INTO schema_migrations(version) VALUES (1)"
                )

    @property
    def schema_version(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
        return int(row["version"] or 0)

    def close(self) -> None:
        """Close the connection; construct a new store to resume access."""
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteMemoryStore":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
