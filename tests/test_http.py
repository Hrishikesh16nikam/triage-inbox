"""End-to-end tests against a real server on a random port."""

import http.client
import json
import threading
import time

from triage.providers import wav_with_transcript
from triage.server import make_server
from triage.worker import Worker
from tests.helpers import AppTestCase


class HttpTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.server = make_server(self.app, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.worker = Worker(self.app.items, 0.05)
        self.worker.start()
        self.make_user("admin", "admin", "admin password 123")
        self.make_user("tri", "triager", "triager password 1")
        self.make_user("view", "viewer", "viewer password 12")

    def tearDown(self):
        self.worker.stop()
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def request(self, method, path, body=None, headers=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = dict(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        data = json.loads(raw) if raw and resp.getheader("Content-Type", "").startswith("application/json") else raw
        return resp, data

    def login(self, username, password):
        resp, data = self.request("POST", "/api/auth/login", {"username": username, "password": password})
        self.assertEqual(resp.status, 200, data)
        cookie = resp.getheader("Set-Cookie")
        return data["access_token"], cookie.split(";")[0]

    def test_security_headers_everywhere(self):
        for path in ("/", "/api/health", "/api/nope"):
            resp, _ = self.request("GET", path)
            self.assertIn("default-src 'self'", resp.getheader("Content-Security-Policy"))
            self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        resp, _ = self.request("GET", "/api/health")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")

    def test_refresh_cookie_is_locked_down(self):
        resp, _ = self.request("POST", "/api/auth/login", {"username": "tri", "password": "triager password 1"})
        cookie = resp.getheader("Set-Cookie")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/api/auth"):
            self.assertIn(flag, cookie)

    def test_full_flow(self):
        token, _ = self.login("tri", "triager password 1")
        resp, item = self.request("POST", "/api/items", wav_with_transcript(
            "Please refill my prescription, I ran out today. Call 555-010-1111."),
            {"X-Filename": "refill%20call.wav", "Content-Type": "application/octet-stream"}, token)
        self.assertEqual(resp.status, 201, item)
        self.assertEqual(item["original_name"], "refill call.wav")

        deadline = time.time() + 5
        while time.time() < deadline:
            _, detail = self.request("GET", f"/api/items/{item['id']}", token=token)
            if detail["status"] == "ready":
                break
            time.sleep(0.05)
        self.assertEqual(detail["status"], "ready")
        self.assertEqual((detail["intent"], detail["urgency"]), ("prescription", "medium"))
        self.assertIn("[PHONE]", detail["redacted_text"])

        resp, updated = self.request("PATCH", f"/api/items/{item['id']}", {"triage_state": "in_progress"}, token=token)
        self.assertEqual((resp.status, updated["triage_state"]), (200, "in_progress"))

        admin, _ = self.login("admin", "admin password 123")
        _, audit = self.request("GET", "/api/audit", token=admin)
        actions = {e["action"] for e in audit["entries"]}
        self.assertTrue({"item.uploaded", "item.processed", "item.viewed", "item.updated"} <= actions)
        _, verify = self.request("GET", "/api/audit/verify", token=admin)
        self.assertTrue(verify["ok"])

    def test_roles_are_enforced(self):
        viewer, _ = self.login("view", "viewer password 12")
        triager, _ = self.login("tri", "triager password 1")
        self.assertEqual(self.request("GET", "/api/items", token=viewer)[0].status, 200)
        self.assertEqual(self.request("POST", "/api/items", b"hi", {"X-Filename": "a.txt"}, viewer)[0].status, 403)
        self.assertEqual(self.request("GET", "/api/audit", token=triager)[0].status, 403)
        self.assertEqual(self.request("POST", "/api/users", {"username": "x"}, token=triager)[0].status, 403)
        self.assertEqual(self.request("GET", "/api/items")[0].status, 401)
        self.assertEqual(self.request("GET", "/api/items", token="garbage")[0].status, 401)

    def test_refresh_flow_over_http(self):
        _, cookie = self.login("tri", "triager password 1")
        resp, data = self.request("POST", "/api/auth/refresh", headers={"Cookie": cookie})
        self.assertEqual(resp.status, 200)
        self.assertIn("access_token", data)
        # replaying the old cookie is reuse: rejected, and the cookie cleared
        resp, _ = self.request("POST", "/api/auth/refresh", headers={"Cookie": cookie})
        self.assertEqual(resp.status, 401)
        self.assertIn("Max-Age=0", resp.getheader("Set-Cookie"))

    def test_cross_origin_refresh_is_rejected(self):
        _, cookie = self.login("tri", "triager password 1")
        resp, _ = self.request("POST", "/api/auth/refresh",
                               headers={"Cookie": cookie, "Origin": "https://evil.example"})
        self.assertEqual(resp.status, 403)

    def test_login_is_rate_limited(self):
        statuses = [self.request("POST", "/api/auth/login", {"username": "tri", "password": "nope nope nope"})[0].status
                    for _ in range(7)]
        self.assertEqual(statuses[:5], [401] * 5)
        self.assertEqual(statuses[5], 429)

    def test_json_endpoints_require_json(self):
        resp, _ = self.request("POST", "/api/auth/login", b"username=tri", {"Content-Type": "text/plain"})
        self.assertEqual(resp.status, 415)

    def test_oversized_body_is_rejected(self):
        token, _ = self.login("tri", "triager password 1")
        self.settings.max_upload_bytes = 100
        resp, _ = self.request("POST", "/api/items", b"x" * 1000, {"X-Filename": "a.txt"}, token)
        self.assertEqual(resp.status, 413)

    def test_static_files_and_traversal(self):
        resp, body = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"Triage Inbox", body)
        for path in ("/static/../config.py", "/static/%2e%2e/config.py", "/etc/passwd"):
            self.assertEqual(self.request("GET", path)[0].status, 404)

    def test_errors_do_not_leak_internals(self):
        token, _ = self.login("tri", "triager password 1")
        resp, data = self.request("GET", "/api/items?limit=abc", token=token)
        self.assertEqual(resp.status, 400)
        self.assertNotIn("Traceback", json.dumps(data))
