"""Business logic: users, authentication and items. HTTP handlers stay
thin and call into these."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .clock import now_iso, now_ts
from .config import Settings
from .db import Database
from .errors import ApiError
from .intake import validate_upload
from .redaction import redact
from .security import passwords, tokens

log = logging.getLogger(__name__)

ROLES = ("viewer", "triager", "admin")  # each role includes the ones before it
MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class Principal:
    id: int
    username: str
    role: str

    def has(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)

    @property
    def actor(self) -> str:
        return f"user:{self.username}"


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class UserService:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def create(self, username: str, password: str, role: str, actor: str) -> dict:
        username = (username or "").strip()
        if not (3 <= len(username) <= 40) or not username.replace("_", "").replace(".", "").replace("-", "").isalnum():
            raise ApiError(400, "username must be 3-40 letters, digits, '.', '_' or '-'")
        if role not in ROLES:
            raise ApiError(400, f"role must be one of {', '.join(ROLES)}")
        try:
            passwords.validate_password(password or "")
        except ValueError as e:
            raise ApiError(400, str(e)) from e
        with self.db.tx() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise ApiError(409, "username already exists")
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                (username, passwords.hash_password(password), role, now_iso()),
            )
            self.audit.record(conn, actor, "user.created", f"user:{username}", {"role": role})
            return self._get(conn, cur.lastrowid)

    def update(self, user_id: int, actor: Principal, *, role: str | None = None, active: bool | None = None) -> dict:
        if role is not None and role not in ROLES:
            raise ApiError(400, f"role must be one of {', '.join(ROLES)}")
        if user_id == actor.id and (active is False or (role and role != "admin")):
            raise ApiError(400, "you can't demote or deactivate yourself")
        with self.db.tx() as conn:
            user = self._get(conn, user_id)
            changes = {}
            if role is not None and role != user["role"]:
                conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
                changes["role"] = role
            if active is not None and active != user["active"]:
                conn.execute("UPDATE users SET active = ? WHERE id = ?", (int(active), user_id))
                changes["active"] = active
                if not active:  # sign them out everywhere
                    conn.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                                 (now_ts(), user_id))
            if changes:
                self.audit.record(conn, actor.actor, "user.updated", f"user:{user['username']}", changes)
            return self._get(conn, user_id)

    def list(self) -> list[dict]:
        with self.db.read() as conn:
            rows = conn.execute("SELECT id, username, role, active, created_at FROM users ORDER BY id").fetchall()
        return [self._public(r) for r in rows]

    def _get(self, conn, user_id: int) -> dict:
        row = conn.execute("SELECT id, username, role, active, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ApiError(404, "user not found")
        return self._public(row)

    @staticmethod
    def _public(row) -> dict:
        return {"id": row["id"], "username": row["username"], "role": row["role"],
                "active": bool(row["active"]), "created_at": row["created_at"]}


class AuthService:
    """Short-lived JWT access tokens plus rotating, opaque refresh tokens.

    Each refresh token can be used once. Using it returns a new one in the
    same "family". If an already-used token is presented again, someone has
    a copy of it (it was stolen, or the real client was), so the whole
    family is revoked and both parties must log in again.
    Refresh tokens are stored only as SHA-256 hashes.
    """

    def __init__(self, db: Database, audit: AuditLog, settings: Settings):
        self.db, self.audit, self.settings = db, audit, settings
        self.jwt_key = settings.subkey("jwt")

    def login(self, username: str, password: str, ip: str) -> tuple[str, str, dict]:
        username = (username or "").strip()[:80]
        with self.db.read() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = passwords.verify_password(password or "", row["password_hash"] if row else passwords.DUMMY_HASH)
        if not row or not ok or not row["active"]:
            with self.db.tx() as conn:
                self.audit.record(conn, "anonymous", "auth.login_failed", f"user:{username}", {"ip": ip})
            raise ApiError(401, "invalid username or password")
        with self.db.tx() as conn:
            if passwords.needs_rehash(row["password_hash"]):
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                             (passwords.hash_password(password), row["id"]))
            refresh = self._issue_refresh(conn, row["id"], family=None)
            self.audit.record(conn, f"user:{row['username']}", "auth.login", None, {"ip": ip})
        user = UserService._public(row)
        return self._access(row), refresh, user

    def refresh(self, raw: str, ip: str) -> tuple[str, str, dict]:
        outcome = None
        with self.db.tx() as conn:
            tok = conn.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (_sha256(raw or ""),)).fetchone()
            if not tok or tok["revoked_at"]:
                outcome = "invalid"
            elif tok["used_at"]:
                # Reuse: revoke the family and commit that before failing.
                conn.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE family = ? AND revoked_at IS NULL",
                             (now_ts(), tok["family"]))
                self.audit.record(conn, "system", "auth.refresh_reuse_detected", f"user_id:{tok['user_id']}",
                                  {"ip": ip, "family": tok["family"][:8]})
                outcome = "reuse"
            elif tok["expires_at"] <= now_ts():
                outcome = "invalid"
            else:
                user = conn.execute("SELECT * FROM users WHERE id = ?", (tok["user_id"],)).fetchone()
                if not user or not user["active"]:
                    outcome = "invalid"
                else:
                    conn.execute("UPDATE refresh_tokens SET used_at = ? WHERE id = ?", (now_ts(), tok["id"]))
                    new_refresh = self._issue_refresh(conn, user["id"], family=tok["family"])
        if outcome is not None:
            raise ApiError(401, "session expired, please log in again")
        return self._access(user), new_refresh, UserService._public(user)

    def logout(self, raw: str, actor: str) -> None:
        with self.db.tx() as conn:
            tok = conn.execute("SELECT family FROM refresh_tokens WHERE token_hash = ?", (_sha256(raw or ""),)).fetchone()
            if tok:
                conn.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE family = ? AND revoked_at IS NULL",
                             (now_ts(), tok["family"]))
                self.audit.record(conn, actor, "auth.logout")

    def authenticate(self, access_token: str) -> Principal:
        try:
            claims = tokens.verify(access_token, self.jwt_key)
        except tokens.TokenError as e:
            raise ApiError(401, "invalid or expired token") from e
        if claims.get("typ") != "access":
            raise ApiError(401, "invalid or expired token")
        # Load the user on every request so deactivation and role changes
        # take effect immediately instead of when the token expires.
        with self.db.read() as conn:
            row = conn.execute("SELECT id, username, role, active FROM users WHERE id = ?",
                               (claims.get("sub"),)).fetchone()
        if not row or not row["active"]:
            raise ApiError(401, "invalid or expired token")
        return Principal(row["id"], row["username"], row["role"])

    def _access(self, user) -> str:
        now = now_ts()
        return tokens.sign({"sub": user["id"], "role": user["role"], "typ": "access", "iat": now,
                            "exp": now + self.settings.access_ttl, "jti": secrets.token_hex(8)}, self.jwt_key)

    def _issue_refresh(self, conn, user_id: int, family: str | None) -> str:
        raw = secrets.token_urlsafe(32)
        now = now_ts()
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, family, expires_at, created_at) VALUES (?,?,?,?,?)",
            (_sha256(raw), user_id, family or secrets.token_hex(16), now + self.settings.refresh_ttl, now),
        )
        return raw


class ItemService:
    LIST_FIELDS = ("id", "kind", "original_name", "status", "triage_state", "intent", "urgency", "sentiment",
                   "summary", "assigned_to", "created_at", "updated_at", "error")
    FILTERS = {"status": ("queued", "processing", "ready", "failed"),
               "triage_state": ("new", "in_progress", "resolved"),
               "urgency": ("high", "medium", "low"),
               "intent": ("appointment", "billing", "prescription", "results", "referral", "complaint", "general")}

    def __init__(self, db: Database, audit: AuditLog, settings: Settings, transcriber, classifier):
        self.db, self.audit, self.settings = db, audit, settings
        self.transcriber, self.classifier = transcriber, classifier
        settings.upload_dir.mkdir(parents=True, exist_ok=True)

    # ---- intake ----------------------------------------------------------

    def create(self, principal: Principal, filename: str, data: bytes) -> dict:
        display, kind = validate_upload(filename, data, self.settings.max_upload_bytes)
        item_id = uuid.uuid4().hex
        stored = item_id  # random name: the user's filename never reaches the filesystem
        path = self.settings.upload_dir / stored
        fd = path.open("xb")
        with fd:
            fd.write(data)
        now = now_iso()
        try:
            with self.db.tx() as conn:
                conn.execute(
                    "INSERT INTO items (id, kind, original_name, stored_name, sha256, size, created_by, created_at,"
                    " updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (item_id, kind, display, stored, hashlib.sha256(data).hexdigest(), len(data), principal.id, now, now),
                )
                self.audit.record(conn, principal.actor, "item.uploaded", f"item:{item_id}",
                                  {"kind": kind, "size": len(data)})
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return self.get(item_id)

    # ---- pipeline --------------------------------------------------------

    def recover_stuck(self) -> int:
        """Requeue items left 'processing' by a crash or restart."""
        with self.db.tx() as conn:
            return conn.execute("UPDATE items SET status = 'queued', updated_at = ? WHERE status = 'processing'",
                                (now_iso(),)).rowcount

    def process_next(self) -> bool:
        with self.db.tx() as conn:  # claim atomically, so two workers never take the same item
            row = conn.execute("SELECT * FROM items WHERE status = 'queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return False
            conn.execute("UPDATE items SET status = 'processing', attempts = attempts + 1, updated_at = ? WHERE id = ?",
                         (now_iso(), row["id"]))
        self._process(row["id"], row["kind"], row["stored_name"], row["attempts"] + 1)
        return True

    def _process(self, item_id: str, kind: str, stored_name: str | None, attempt: int) -> None:
        path = self.settings.upload_dir / (stored_name or "")
        try:
            if not stored_name or not path.is_file():
                raise RuntimeError("uploaded file is missing")
            text = self.transcriber.transcribe(path) if kind == "audio" else path.read_text(encoding="utf-8")
            if not text.strip():
                raise RuntimeError("no text could be extracted")
            redacted, counts = redact(text)
            del text  # the raw text is never stored
            result = self.classifier.classify(redacted)
        except Exception as e:
            log.warning("processing item %s failed (attempt %d): %s", item_id, attempt, e)
            status = "failed" if attempt >= MAX_ATTEMPTS else "queued"
            with self.db.tx() as conn:
                conn.execute("UPDATE items SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                             (status, str(e)[:300], now_iso(), item_id))
                if status == "failed":
                    self.audit.record(conn, "system", "item.failed", f"item:{item_id}", {"attempts": attempt})
            return

        with self.db.tx() as conn:
            conn.execute(
                "UPDATE items SET status = 'ready', error = NULL, intent = ?, urgency = ?, sentiment = ?, summary = ?,"
                " redacted_text = ?, redactions = ?, updated_at = ? WHERE id = ?",
                (result.intent, result.urgency, result.sentiment, result.summary, redacted,
                 json.dumps(counts), now_iso(), item_id),
            )
            if not self.settings.keep_uploads:
                conn.execute("UPDATE items SET stored_name = NULL WHERE id = ?", (item_id,))
            self.audit.record(conn, "system", "item.processed", f"item:{item_id}",
                              {"intent": result.intent, "urgency": result.urgency, "redactions": counts,
                               "classifier": getattr(self.classifier, "name", "?")})
        if not self.settings.keep_uploads:
            path.unlink(missing_ok=True)

    # ---- reading and triage ---------------------------------------------

    def list(self, filters: dict, limit: int = 50, offset: int = 0) -> dict:
        where, args = [], []
        for key, allowed in self.FILTERS.items():
            value = filters.get(key)
            if value:
                if value not in allowed:
                    raise ApiError(400, f"invalid {key}")
                where.append(f"{key} = ?")
                args.append(value)
        if filters.get("assigned_to"):
            where.append("assigned_to = ?")
            args.append(int(filters["assigned_to"]))
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit, offset = max(1, min(limit, 200)), max(0, offset)
        order = ("CASE urgency WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,"
                 " created_at DESC")
        with self.db.read() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS n FROM items {clause}", args).fetchone()["n"]
            rows = conn.execute(f"SELECT {', '.join(self.LIST_FIELDS)} FROM items {clause} ORDER BY {order}"
                                f" LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        return {"total": total, "items": [dict(r) for r in rows]}

    def get(self, item_id: str) -> dict:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT i.*, u.username AS assignee FROM items i LEFT JOIN users u ON u.id = i.assigned_to"
                " WHERE i.id = ?", (item_id,)).fetchone()
        if not row:
            raise ApiError(404, "item not found")
        item = {k: row[k] for k in (*self.LIST_FIELDS, "size", "sha256", "redacted_text", "assignee", "attempts")}
        item["redactions"] = json.loads(row["redactions"]) if row["redactions"] else {}
        return item

    def view(self, principal: Principal, item_id: str) -> dict:
        """Read an item's full content. Reads of message content are audited,
        as access to health information should be."""
        item = self.get(item_id)
        with self.db.tx() as conn:
            self.audit.record(conn, principal.actor, "item.viewed", f"item:{item_id}")
        return item

    def update(self, principal: Principal, item_id: str, changes: dict) -> dict:
        allowed = {"triage_state", "assigned_to"}
        unknown = set(changes) - allowed
        if unknown:
            raise ApiError(400, f"can't change: {', '.join(sorted(unknown))}")
        with self.db.tx() as conn:
            row = conn.execute("SELECT triage_state, assigned_to, status FROM items WHERE id = ?", (item_id,)).fetchone()
            if not row:
                raise ApiError(404, "item not found")
            applied = {}
            if "triage_state" in changes:
                state = changes["triage_state"]
                if state not in self.FILTERS["triage_state"]:
                    raise ApiError(400, "invalid triage_state")
                if row["status"] != "ready":
                    raise ApiError(409, "item hasn't finished processing")
                if state != row["triage_state"]:
                    applied["triage_state"] = state
            if "assigned_to" in changes:
                assignee = changes["assigned_to"]
                if assignee is not None:
                    user = conn.execute("SELECT id, role, active FROM users WHERE id = ?", (assignee,)).fetchone()
                    if not user or not user["active"] or user["role"] == "viewer":
                        raise ApiError(400, "can only assign to an active triager or admin")
                if assignee != row["assigned_to"]:
                    applied["assigned_to"] = assignee
            if applied:
                sets = ", ".join(f"{k} = ?" for k in applied)
                conn.execute(f"UPDATE items SET {sets}, updated_at = ? WHERE id = ?",
                             [*applied.values(), now_iso(), item_id])
                self.audit.record(conn, principal.actor, "item.updated", f"item:{item_id}", applied)
        return self.get(item_id)

    def delete(self, principal: Principal, item_id: str) -> None:
        with self.db.tx() as conn:
            row = conn.execute("SELECT stored_name FROM items WHERE id = ?", (item_id,)).fetchone()
            if not row:
                raise ApiError(404, "item not found")
            conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
            self.audit.record(conn, principal.actor, "item.deleted", f"item:{item_id}")
        if row["stored_name"]:
            (self.settings.upload_dir / row["stored_name"]).unlink(missing_ok=True)
