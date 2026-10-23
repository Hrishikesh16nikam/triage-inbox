"""Show the audit log catching tampering, on a throwaway copy of the database.

    python scripts/tamper_demo.py            # uses data/triage.db
    python scripts/tamper_demo.py path/to/triage.db

Plays the attacker: copies the database, drops the append-only triggers,
rewrites one audit entry to hide who did something, then runs the same
verification the app uses. Your real database is never modified.
"""

from __future__ import annotations

import hashlib
import hmac
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from triage.audit import AuditLog  # noqa: E402
from triage.config import load_secret  # noqa: E402
from triage.db import Database  # noqa: E402


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "data/triage.db")
    if not source.exists():
        print(f"{source} not found; run the app and seed-demo first")
        return 1
    key = hmac.new(load_secret(source.parent), b"audit", hashlib.sha256).digest()

    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "triage.db"
        src = sqlite3.connect(source)
        dst = sqlite3.connect(copy)
        src.backup(dst)  # consistent copy, including anything still in the WAL
        src.close()

        audit = AuditLog(Database(copy), key)
        before = audit.verify()
        print(f"before: ok={before.ok}, {before.checked} entries")
        if before.checked < 2:
            print("need at least 2 audit entries; use the app a little first")
            return 1

        target = dst.execute("SELECT id, actor, action FROM audit_log ORDER BY id LIMIT 1 OFFSET 1").fetchone()
        print(f"attacker rewrites entry {target[0]} ({target[1]} {target[2]}) to actor 'user:someone-else'")
        dst.execute("DROP TRIGGER audit_log_no_update")
        dst.execute("UPDATE audit_log SET actor = 'user:someone-else' WHERE id = ?", (target[0],))
        dst.commit()
        dst.close()

        after = audit.verify()
        print(f"after:  ok={after.ok}, broken at entry {after.broken_at}: {after.reason}")
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if not after.ok else 1


if __name__ == "__main__":
    sys.exit(main())
