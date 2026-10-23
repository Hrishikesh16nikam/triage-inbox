"""SQLite access. One short-lived connection per unit of work keeps the
code thread-safe without a connection pool."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL CHECK (role IN ('admin', 'triager', 'viewer')),
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE refresh_tokens (
            id         INTEGER PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            family     TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at    INTEGER,
            revoked_at INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX ix_refresh_family ON refresh_tokens(family);

        CREATE TABLE items (
            id            TEXT PRIMARY KEY,
            kind          TEXT NOT NULL CHECK (kind IN ('audio', 'document')),
            original_name TEXT NOT NULL,
            stored_name   TEXT,
            sha256        TEXT NOT NULL,
            size          INTEGER NOT NULL,
            status        TEXT NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued', 'processing', 'ready', 'failed')),
            attempts      INTEGER NOT NULL DEFAULT 0,
            error         TEXT,
            triage_state  TEXT NOT NULL DEFAULT 'new'
                          CHECK (triage_state IN ('new', 'in_progress', 'resolved')),
            intent        TEXT,
            urgency       TEXT,
            sentiment     TEXT,
            summary       TEXT,
            redacted_text TEXT,
            redactions    TEXT,
            assigned_to   INTEGER REFERENCES users(id),
            created_by    INTEGER NOT NULL REFERENCES users(id),
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        );
        CREATE INDEX ix_items_status ON items(status, created_at);

        CREATE TABLE audit_log (
            id       INTEGER PRIMARY KEY,
            ts       TEXT NOT NULL,
            actor    TEXT NOT NULL,
            action   TEXT NOT NULL,
            target   TEXT,
            detail   TEXT NOT NULL,
            prev_mac TEXT NOT NULL,
            mac      TEXT NOT NULL
        );
        -- Defense in depth: the application can never rewrite history.
        -- Someone with raw file access can drop these triggers, which is
        -- why every row is also chained with an HMAC (see audit.py).
        CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
        CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
        """,
    ),
]


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """A write transaction. BEGIN IMMEDIATE takes the write lock up
        front, which serializes writers (the audit chain relies on this)."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def migrate(self) -> int:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            current = row["v"] or 0
            for version, sql in MIGRATIONS:
                if version > current:
                    conn.executescript(f"BEGIN;\n{sql}\nINSERT INTO schema_version VALUES ({version});\nCOMMIT;")
                    current = version
            return current
        finally:
            conn.close()
