"""HTTP layer on the standard library's ThreadingHTTPServer.

Routing, auth, rate limits, body limits and security headers live here;
everything else is in services.py.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .audit import AuditLog
from .config import Settings
from .db import Database
from .errors import ApiError
from .providers import make_classifier, make_transcriber
from .security.ratelimit import RateLimiter
from .services import AuthService, ItemService, Principal, UserService

log = logging.getLogger("triage.http")

REFRESH_COOKIE = "triage_refresh"
MAX_JSON_BYTES = 64 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                                "form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


@dataclass
class Request:
    method: str
    path: str
    query: dict
    headers: dict
    client_ip: str
    read_body: Callable[[int], bytes]
    params: dict = field(default_factory=dict)
    principal: Principal | None = None

    def json(self) -> dict:
        if "application/json" not in self.headers.get("content-type", ""):
            raise ApiError(415, "expected application/json")
        try:
            data = json.loads(self.read_body(MAX_JSON_BYTES) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ApiError(400, "invalid JSON body") from e
        if not isinstance(data, dict):
            raise ApiError(400, "JSON body must be an object")
        return data

    def cookie(self, name: str) -> str | None:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("cookie", ""))
        except Exception:
            return None
        return jar[name].value if name in jar else None

    def q(self, name: str, default: str | None = None) -> str | None:
        values = self.query.get(name)
        return values[0] if values else default


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)


def json_response(status: int, obj, **kw) -> Response:
    return Response(status, json.dumps(obj).encode(), **kw)


class App:
    def __init__(self, settings: Settings, *, transcriber=None, classifier=None):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.db.migrate()
        self.audit = AuditLog(self.db, settings.subkey("audit"))
        self.users = UserService(self.db, self.audit)
        self.auth = AuthService(self.db, self.audit, settings)
        self.items = ItemService(
            self.db, self.audit, settings,
            transcriber or make_transcriber(settings.transcriber),
            classifier or make_classifier(settings.classifier, ollama_url=settings.ollama_url,
                                          ollama_model=settings.ollama_model),
        )
        self.login_limiter = RateLimiter(5, 60)  # per IP
        self.refresh_limiter = RateLimiter(30, 60)  # per IP
        self.upload_limiter = RateLimiter(30, 60)  # per user
        self.static = self._load_static()
        self.routes: list[tuple[str, re.Pattern, Callable, str | None]] = []
        self._register_routes()

    # ---- routing ---------------------------------------------------------

    def route(self, method: str, pattern: str, role: str | None):
        def deco(fn):
            self.routes.append((method, re.compile(f"^{pattern}$"), fn, role))
            return fn
        return deco

    def dispatch(self, req: Request) -> Response:
        try:
            if req.method == "GET" and not req.path.startswith("/api/"):
                return self._serve_static(req.path)
            allowed_methods = set()
            for method, pattern, fn, role in self.routes:
                m = pattern.match(req.path)
                if not m:
                    continue
                allowed_methods.add(method)
                if method != req.method:
                    continue
                req.params = m.groupdict()
                if role is not None:
                    req.principal = self._require(req, role)
                return fn(req)
            if allowed_methods:
                return json_response(405, {"error": "method not allowed"},
                                     headers={"Allow": ", ".join(sorted(allowed_methods))})
            return json_response(404, {"error": "not found"})
        except ApiError as e:
            return json_response(e.status, {"error": e.message}, headers=e.headers)
        except Exception:
            log.exception("unhandled error on %s %s", req.method, req.path)
            return json_response(500, {"error": "internal error"})  # never leak details

    def _require(self, req: Request, role: str) -> Principal:
        header = req.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise ApiError(401, "missing bearer token", {"WWW-Authenticate": "Bearer"})
        principal = self.auth.authenticate(header[7:].strip())
        if not principal.has(role):
            raise ApiError(403, f"requires the {role} role")
        return principal

    def _same_origin(self, req: Request) -> None:
        """Cookie-authenticated endpoints also check Origin, on top of the
        SameSite=Strict cookie, as a second layer against CSRF."""
        origin = req.headers.get("origin")
        if origin and urlsplit(origin).netloc != req.headers.get("host"):
            raise ApiError(403, "cross-origin request rejected")

    def _limit(self, limiter: RateLimiter, key: str) -> None:
        ok, retry = limiter.allow(key)
        if not ok:
            raise ApiError(429, "too many requests, slow down", {"Retry-After": str(max(1, int(retry + 0.999)))})

    def _refresh_cookie(self, value: str, max_age: int) -> str:
        parts = [f"{REFRESH_COOKIE}={value}", "HttpOnly", "SameSite=Strict", "Path=/api/auth", f"Max-Age={max_age}"]
        if self.settings.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def _session(self, status: int, access: str, refresh: str, user: dict) -> Response:
        return json_response(status, {"access_token": access, "token_type": "Bearer",
                                      "expires_in": self.settings.access_ttl, "user": user},
                             cookies=[self._refresh_cookie(refresh, self.settings.refresh_ttl)])

    # ---- static files ----------------------------------------------------

    @staticmethod
    def _load_static() -> dict[str, tuple[bytes, str]]:
        # Load an explicit allowlist at startup: request paths are only ever
        # dictionary keys, so there is no filesystem path to traverse.
        files = {}
        root = resources.files("triage") / "static"
        for entry in root.iterdir():
            ext = entry.name[entry.name.rfind("."):]
            if entry.is_file() and ext in STATIC_TYPES:
                files[f"/static/{entry.name}"] = (entry.read_bytes(), STATIC_TYPES[ext])
        if "/static/index.html" in files:
            files["/"] = files["/static/index.html"]
        return files

    def _serve_static(self, path: str) -> Response:
        hit = self.static.get(path)
        if not hit:
            return Response(404, b"not found", "text/plain; charset=utf-8")
        body, ctype = hit
        return Response(200, body, ctype, headers={"Cache-Control": "no-cache"})

    # ---- endpoints -------------------------------------------------------

    def _register_routes(self) -> None:
        r = self.route

        @r("GET", "/api/health", None)
        def health(req):
            return json_response(200, {"status": "ok"})

        @r("POST", "/api/auth/login", None)
        def login(req):
            self._limit(self.login_limiter, req.client_ip)
            body = req.json()
            access, refresh, user = self.auth.login(str(body.get("username", "")), str(body.get("password", "")),
                                                    req.client_ip)
            return self._session(200, access, refresh, user)

        @r("POST", "/api/auth/refresh", None)
        def refresh(req):
            self._same_origin(req)
            self._limit(self.refresh_limiter, req.client_ip)
            raw = req.cookie(REFRESH_COOKIE)
            if not raw:
                raise ApiError(401, "no session")
            try:
                access, new_refresh, user = self.auth.refresh(raw, req.client_ip)
            except ApiError as e:
                e.headers["Set-Cookie"] = self._refresh_cookie("", 0)
                raise
            return self._session(200, access, new_refresh, user)

        @r("POST", "/api/auth/logout", None)
        def logout(req):
            self._same_origin(req)
            raw = req.cookie(REFRESH_COOKIE)
            if raw:
                self.auth.logout(raw, "user")
            return Response(204, cookies=[self._refresh_cookie("", 0)])

        @r("GET", "/api/me", "viewer")
        def me(req):
            p = req.principal
            return json_response(200, {"id": p.id, "username": p.username, "role": p.role})

        @r("GET", "/api/items", "viewer")
        def list_items(req):
            filters = {k: req.q(k) for k in ("status", "triage_state", "urgency", "intent", "assigned_to")}
            try:
                limit, offset = int(req.q("limit", "50")), int(req.q("offset", "0"))
            except ValueError as e:
                raise ApiError(400, "limit and offset must be integers") from e
            return json_response(200, self.items.list(filters, limit, offset))

        @r("POST", "/api/items", "triager")
        def upload(req):
            self._limit(self.upload_limiter, f"user:{req.principal.id}")
            filename = unquote(req.headers.get("x-filename", ""))  # sent URL-encoded so any name fits in a header
            data = req.read_body(self.settings.max_upload_bytes)
            return json_response(201, self.items.create(req.principal, filename, data))

        @r("GET", "/api/items/(?P<id>[0-9a-f]{32})", "viewer")
        def get_item(req):
            return json_response(200, self.items.view(req.principal, req.params["id"]))

        @r("PATCH", "/api/items/(?P<id>[0-9a-f]{32})", "triager")
        def update_item(req):
            return json_response(200, self.items.update(req.principal, req.params["id"], req.json()))

        @r("DELETE", "/api/items/(?P<id>[0-9a-f]{32})", "admin")
        def delete_item(req):
            self.items.delete(req.principal, req.params["id"])
            return Response(204)

        @r("GET", "/api/users", "triager")
        def list_users(req):
            users = self.users.list()
            if not req.principal.has("admin"):  # triagers only need names to assign work
                users = [{"id": u["id"], "username": u["username"], "role": u["role"]}
                         for u in users if u["active"] and u["role"] != "viewer"]
            return json_response(200, {"users": users})

        @r("POST", "/api/users", "admin")
        def create_user(req):
            body = req.json()
            user = self.users.create(str(body.get("username", "")), str(body.get("password", "")),
                                     str(body.get("role", "")), req.principal.actor)
            return json_response(201, user)

        @r("PATCH", "/api/users/(?P<id>[0-9]+)", "admin")
        def update_user(req):
            body = req.json()
            active = body.get("active")
            if active is not None and not isinstance(active, bool):
                raise ApiError(400, "active must be true or false")
            return json_response(200, self.users.update(int(req.params["id"]), req.principal,
                                                        role=body.get("role"), active=active))

        @r("GET", "/api/audit", "admin")
        def audit_list(req):
            try:
                limit = int(req.q("limit", "100"))
                before = int(req.q("before")) if req.q("before") else None
            except ValueError as e:
                raise ApiError(400, "limit and before must be integers") from e
            return json_response(200, {"entries": self.audit.list(limit, before)})

        @r("GET", "/api/audit/verify", "admin")
        def audit_verify(req):
            result = self.audit.verify()
            return json_response(200, result.__dict__)


def make_handler(app: App, *, trust_proxy: bool = False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "triage-inbox"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _handle(self):
            start = time.perf_counter()
            split = urlsplit(self.path)
            headers = {k.lower(): v for k, v in self.headers.items()}
            ip = self.client_address[0]
            if trust_proxy and headers.get("x-forwarded-for"):
                ip = headers["x-forwarded-for"].split(",")[0].strip()
            consumed = {"done": False}

            def read_body(limit: int) -> bytes:
                consumed["done"] = True
                if "chunked" in headers.get("transfer-encoding", "").lower():
                    raise ApiError(411, "chunked bodies are not supported; send Content-Length")
                try:
                    length = int(headers.get("content-length", "0"))
                except ValueError as e:
                    raise ApiError(400, "invalid Content-Length") from e
                if length < 0:
                    raise ApiError(400, "invalid Content-Length")
                if length > limit:
                    self.close_connection = True  # don't read an oversized body at all
                    raise ApiError(413, "request body too large")
                return self.rfile.read(length)

            req = Request(self.command, split.path, parse_qs(split.query), headers, ip, read_body)
            resp = app.dispatch(req)
            if not consumed["done"] and headers.get("content-length", "0") not in ("", "0"):
                self.close_connection = True  # unread body would corrupt keep-alive
            self._send(resp)
            log.info("%s %s %d %.1fms", self.command, split.path, resp.status, (time.perf_counter() - start) * 1000)

        def _send(self, resp: Response):
            self.send_response(resp.status)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            if app.settings.secure_cookies:
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            if resp.body or resp.status not in (204, 304):
                self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            if resp.content_type == "application/json":
                self.send_header("Cache-Control", "no-store")
            for k, v in resp.headers.items():
                self.send_header(k, v)
            for c in resp.cookies:
                self.send_header("Set-Cookie", c)
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp.body)

        do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = _handle

        def log_message(self, fmt, *args):  # route http.server's own logging through ours
            log.debug(fmt, *args)

    return Handler


def make_server(app: App, host: str, port: int, *, trust_proxy: bool = False) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(app, trust_proxy=trust_proxy))
    server.daemon_threads = True
    return server
