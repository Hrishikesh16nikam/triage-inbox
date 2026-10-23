import sqlite3

from tests.helpers import AppTestCase


class AuditTests(AppTestCase):
    def write(self, n):
        for i in range(n):
            with self.app.db.tx() as conn:
                self.app.audit.record(conn, "user:test", "thing.happened", f"thing:{i}", {"n": i})

    def raw_conn(self):
        conn = sqlite3.connect(self.settings.db_path)
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("DROP TRIGGER audit_log_no_delete")
        return conn

    def test_clean_chain_verifies(self):
        self.write(5)
        result = self.app.audit.verify()
        self.assertTrue(result.ok)
        self.assertEqual(result.checked, 5)

    def test_triggers_block_updates_and_deletes(self):
        self.write(1)
        with self.app.db.read() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE audit_log SET actor = 'mallory'")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM audit_log")

    def test_edited_entry_is_detected(self):
        self.write(4)
        conn = self.raw_conn()  # an attacker with direct file access
        conn.execute("UPDATE audit_log SET actor = 'user:mallory' WHERE id = 2")
        conn.commit()
        result = self.app.audit.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)
        self.assertIn("modified", result.reason)

    def test_deleted_entry_is_detected(self):
        self.write(4)
        conn = self.raw_conn()
        conn.execute("DELETE FROM audit_log WHERE id = 2")
        conn.commit()
        result = self.app.audit.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 3)

    def test_forged_chain_without_key_is_detected(self):
        """Recomputing hashes doesn't help without the HMAC key."""
        import hashlib
        self.write(2)
        conn = self.raw_conn()
        row = conn.execute("SELECT * FROM audit_log WHERE id = 2").fetchone()
        fake = hashlib.sha256(b"attacker recomputed this").hexdigest()
        conn.execute("UPDATE audit_log SET detail = '{}', mac = ? WHERE id = 2", (fake,))
        conn.commit()
        self.assertFalse(self.app.audit.verify().ok)
        self.assertIsNotNone(row)

    def test_list_is_newest_first(self):
        self.write(3)
        entries = self.app.audit.list(limit=2)
        self.assertEqual([e["id"] for e in entries], [3, 2])
        self.assertEqual(self.app.audit.list(before_id=2)[0]["id"], 1)
