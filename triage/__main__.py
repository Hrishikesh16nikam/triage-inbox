"""Command line: python -m triage <command>"""

from __future__ import annotations

import argparse
import getpass
import logging
import secrets
import sys
from pathlib import Path

from .config import Settings
from .errors import ApiError
from .providers import wav_with_transcript
from .server import App, make_server
from .services import Principal
from .worker import Worker

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def cmd_serve(args, settings: Settings) -> int:
    app = App(settings)
    worker = Worker(app.items, settings.worker_poll_seconds)
    worker.start()
    server = make_server(app, args.host, args.port, trust_proxy=args.trust_proxy)
    logging.getLogger("triage").info("Triage Inbox on http://%s:%d (transcriber=%s, classifier=%s)",
                                     args.host, args.port, settings.transcriber, settings.classifier)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
        server.server_close()
    return 0


def cmd_create_user(args, settings: Settings) -> int:
    app = App(settings)
    password = args.password or getpass.getpass("Password (min 12 characters): ")
    try:
        user = app.users.create(args.username, password, args.role, "cli")
    except ApiError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    print(f"created {user['role']} {user['username']}")
    return 0


def cmd_verify_audit(args, settings: Settings) -> int:
    result = App(settings).audit.verify()
    if result.ok:
        print(f"OK: {result.checked} entries verified, head {result.head or '-'}")
        return 0
    print(f"TAMPERED: entry {result.broken_at}: {result.reason} ({result.checked} entries verified before it)")
    return 2


def cmd_seed_demo(args, settings: Settings) -> int:
    app = App(settings)
    created = []
    for username, role in (("admin", "admin"), ("triager", "triager"), ("viewer", "viewer")):
        password = secrets.token_urlsafe(12)
        try:
            app.users.create(username, password, role, "cli:seed")
            created.append((username, role, password))
        except ApiError as e:
            if e.status != 409:
                raise
    with app.db.read() as conn:
        triager = conn.execute("SELECT id, username, role FROM users WHERE username = 'triager'").fetchone()
    actor = Principal(triager["id"], triager["username"], triager["role"])

    count = 0
    for path in sorted((SAMPLES / "voicemails").glob("*.txt")):
        app.items.create(actor, path.with_suffix(".wav").name, wav_with_transcript(path.read_text(encoding="utf-8")))
        count += 1
    for path in sorted((SAMPLES / "documents").glob("*")):
        if path.suffix in (".txt", ".md"):
            app.items.create(actor, path.name, path.read_bytes())
            count += 1

    print(f"queued {count} sample items (the server's worker processes them)")
    if created:
        print("\ndemo accounts (shown once, store them somewhere safe):")
        for username, role, password in created:
            print(f"  {username:<8} {role:<8} {password}")
    else:
        print("demo accounts already exist")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage", description="Triage Inbox")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the web server and background worker")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--trust-proxy", action="store_true", help="use X-Forwarded-For for client IPs")
    serve.set_defaults(fn=cmd_serve)

    cu = sub.add_parser("create-user", help="create an account")
    cu.add_argument("username")
    cu.add_argument("--role", choices=("admin", "triager", "viewer"), default="triager")
    cu.add_argument("--password", help="omit to be prompted (safer: keeps it out of shell history)")
    cu.set_defaults(fn=cmd_create_user)

    sub.add_parser("verify-audit", help="check the audit log's integrity").set_defaults(fn=cmd_verify_audit)
    sub.add_parser("seed-demo", help="create demo accounts and queue synthetic samples").set_defaults(fn=cmd_seed_demo)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    return args.fn(args, Settings.from_env())


if __name__ == "__main__":
    sys.exit(main())
