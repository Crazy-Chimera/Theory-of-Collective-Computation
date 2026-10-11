"""SQLite-backed identity registry and deny-by-default authorization policy."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from threading import RLock
from .identity import AuthorizationError, AuthorizationPolicy, Identity, IdentityError, IdentityRegistry, Permission, SubjectType

def _connect(path):
    path = str(path)
    if path != ":memory:":
        Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS identity_migrations(version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        version = db.execute("SELECT MAX(version) v FROM identity_migrations").fetchone()["v"] or 0
        if version > 1:
            raise RuntimeError("database schema newer than this implementation")
        if version == 0:
            db.execute("""CREATE TABLE identities(identity_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                subject_type TEXT NOT NULL CHECK(subject_type IN ('human','agent','organization')),
                parent_identity_id TEXT REFERENCES identities(identity_id),
                CHECK(parent_identity_id IS NULL OR parent_identity_id <> identity_id))""")
            db.execute("""CREATE TABLE grants(subject_id TEXT NOT NULL, resource_id TEXT NOT NULL,
                permission TEXT NOT NULL, PRIMARY KEY(subject_id,resource_id,permission))""")
            db.execute("""CREATE TABLE identity_audit(event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL, subject_id TEXT NOT NULL, resource_id TEXT,
                permission TEXT, occurred_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
            db.execute("""CREATE TRIGGER identity_immutable BEFORE UPDATE ON identities BEGIN
                SELECT RAISE(ABORT,'identity records are immutable'); END""")
            db.execute("""CREATE TRIGGER identity_no_delete BEFORE DELETE ON identities BEGIN
                SELECT RAISE(ABORT,'identity records are append-only'); END""")
            db.execute("""CREATE TRIGGER audit_no_update BEFORE UPDATE ON identity_audit BEGIN
                SELECT RAISE(ABORT,'audit history is append-only'); END""")
            db.execute("""CREATE TRIGGER audit_no_delete BEFORE DELETE ON identity_audit BEGIN
                SELECT RAISE(ABORT,'audit history is append-only'); END""")
            db.execute("INSERT INTO identity_migrations(version) VALUES(1)")
    return db

class SQLiteIdentityRegistry(IdentityRegistry):
    """Persists identities and controller/parent relationships."""
    def __init__(self, database_path):
        super().__init__()
        self.database_path = str(database_path)
        self._lock = RLock()
        self._db = _connect(database_path)

    def register(self, identity: Identity) -> Identity:
        if not isinstance(identity, Identity):
            raise IdentityError("identity must be an Identity")
        with self._lock, self._db:
            if self.get(identity.identity_id) is not None:
                raise IdentityError(f"identity already registered: {identity.identity_id}")
            if identity.parent_identity_id and self.get(identity.parent_identity_id) is None:
                raise IdentityError(f"unknown parent identity: {identity.parent_identity_id}")
            try:
                self._db.execute("INSERT INTO identities VALUES(?,?,?,?)",
                    (identity.identity_id, identity.display_name, identity.subject_type.value, identity.parent_identity_id))
                self._db.execute("INSERT INTO identity_audit(event_type,subject_id) VALUES('identity_registered',?)",
                    (identity.identity_id,))
            except sqlite3.IntegrityError as exc:
                raise IdentityError("identity registration rejected") from exc
        return identity

    def get(self, identity_id: str) -> Identity | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM identities WHERE identity_id=?", (identity_id,)).fetchone()
        if row is None:
            return None
        return Identity(row["identity_id"], row["display_name"], SubjectType(row["subject_type"]), row["parent_identity_id"])

    def __len__(self):
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM identities").fetchone()[0]

    @property
    def schema_version(self):
        with self._lock:
            return self._db.execute("SELECT MAX(version) FROM identity_migrations").fetchone()[0] or 0

    def close(self):
        with self._lock:
            self._db.close()

    def __enter__(self): return self
    def __exit__(self, exc_type, exc, traceback): self.close()

class SQLiteAuthorizationPolicy(AuthorizationPolicy):
    """Persists explicit grants/revocations and metadata audit events."""
    def __init__(self, database_path):
        super().__init__()
        self.database_path = str(database_path)
        self._lock = RLock()
        self._db = _connect(database_path)

    def grant(self, subject_id: str, resource_id: str, permission: Permission):
        if not isinstance(subject_id, str) or not subject_id.strip() or not isinstance(resource_id, str) or not resource_id.strip():
            raise AuthorizationError("subject_id and resource_id must not be empty")
        if not isinstance(permission, Permission):
            raise AuthorizationError("permission must be a Permission")
        with self._lock, self._db:
            cur = self._db.execute("INSERT OR IGNORE INTO grants VALUES(?,?,?)",
                (subject_id, resource_id, permission.value))
            if cur.rowcount:
                self._db.execute("INSERT INTO identity_audit(event_type,subject_id,resource_id,permission) VALUES('grant_created',?,?,?)",
                    (subject_id, resource_id, permission.value))

    def revoke(self, subject_id: str, resource_id: str, permission: Permission):
        if not isinstance(permission, Permission):
            raise AuthorizationError("permission must be a Permission")
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM grants WHERE subject_id=? AND resource_id=? AND permission=?",
                (subject_id, resource_id, permission.value))
            if cur.rowcount:
                self._db.execute("INSERT INTO identity_audit(event_type,subject_id,resource_id,permission) VALUES('grant_revoked',?,?,?)",
                    (subject_id, resource_id, permission.value))

    def is_allowed(self, subject_id: str, resource_id: str, permission: Permission) -> bool:
        if not isinstance(permission, Permission): return False
        with self._lock:
            return self._db.execute("SELECT 1 FROM grants WHERE subject_id=? AND resource_id=? AND permission=?",
                (subject_id, resource_id, permission.value)).fetchone() is not None

    def audit_events(self):
        with self._lock:
            return [dict(r) for r in self._db.execute("SELECT * FROM identity_audit ORDER BY event_id").fetchall()]

    @property
    def schema_version(self):
        with self._lock:
            return self._db.execute("SELECT MAX(version) FROM identity_migrations").fetchone()[0] or 0

    def close(self):
        with self._lock: self._db.close()

    def __enter__(self): return self
    def __exit__(self, exc_type, exc, traceback): self.close()
