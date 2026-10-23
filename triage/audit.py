"""Tamper-evident audit log.

Each entry stores an HMAC over its own fields plus the previous entry's
HMAC, forming a chain. Changing, reordering or deleting any entry breaks
every link after it, and because the chain is keyed, someone with write
access to the database but not the key cannot forge a replacement chain.

Entries are written inside the caller's transaction, so an action and its
audit record commit together or not at all.

Known limit: deleting the newest entries leaves a shorter chain that still
verifies. Periodically exporting the head (id + mac) somewhere external
closes that gap; see docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass

from .clock import now_iso
from .db import Database

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None
    head: str | None = None


class AuditLog:
    def __init__(self, db: Database, key: bytes):
        self.db = db
        self.key = key

    def _mac(self, entry_id: int, prev_mac: str, ts: str, actor: str, action: str, target, detail: str) -> str:
        msg = _canonical([entry_id, prev_mac, ts, actor, action, target, detail]).encode()
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()

    def record(self, conn: sqlite3.Connection, actor: str, action: str, target: str | None = None,
               detail: dict | None = None) -> int:
        last = conn.execute("SELECT id, mac FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        entry_id = (last["id"] + 1) if last else 1
        prev_mac = last["mac"] if last else GENESIS
        ts = now_iso()
        detail_json = _canonical(detail or {})
        mac = self._mac(entry_id, prev_mac, ts, actor, action, target, detail_json)
        conn.execute(
            "INSERT INTO audit_log (id, ts, actor, action, target, detail, prev_mac, mac) VALUES (?,?,?,?,?,?,?,?)",
            (entry_id, ts, actor, action, target, detail_json, prev_mac, mac),
        )
        return entry_id

    def verify(self) -> VerifyResult:
        expected_prev = GENESIS
        expected_id = 1
        checked = 0
        with self.db.read() as conn:
            for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
                if row["id"] != expected_id:
                    return VerifyResult(False, checked, row["id"], f"gap: expected entry {expected_id}")
                if row["prev_mac"] != expected_prev:
                    return VerifyResult(False, checked, row["id"], "chain link does not match previous entry")
                mac = self._mac(row["id"], row["prev_mac"], row["ts"], row["actor"], row["action"],
                                row["target"], row["detail"])
                if not hmac.compare_digest(mac, row["mac"]):
                    return VerifyResult(False, checked, row["id"], "entry contents were modified")
                expected_prev = row["mac"]
                expected_id += 1
                checked += 1
        return VerifyResult(True, checked, head=expected_prev if checked else None)

    def list(self, limit: int = 100, before_id: int | None = None) -> list[dict]:
        limit = max(1, min(limit, 500))
        with self.db.read() as conn:
            if before_id:
                rows = conn.execute("SELECT * FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?",
                                    (before_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {"id": r["id"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
             "target": r["target"], "detail": json.loads(r["detail"])}
            for r in rows
        ]
