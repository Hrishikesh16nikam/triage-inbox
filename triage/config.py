"""Settings, read from environment variables with safe defaults."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    data_dir: Path = Path("data")
    secret_key: bytes = b""
    access_ttl: int = 15 * 60  # seconds
    refresh_ttl: int = 7 * 24 * 3600
    max_upload_bytes: int = 10 * 1024 * 1024
    transcriber: str = "mock"  # mock | whisper
    classifier: str = "rules"  # rules | ollama
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    keep_uploads: bool = False  # delete raw files once processed (data minimization)
    secure_cookies: bool = False  # set True behind HTTPS
    worker_poll_seconds: float = 1.0

    @property
    def db_path(self) -> Path:
        return self.data_dir / "triage.db"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    # Separate keys for separate jobs, all derived from one secret, so a
    # weakness in one use can't be replayed against another.
    def subkey(self, purpose: str) -> bytes:
        return hmac.new(self.secret_key, purpose.encode(), hashlib.sha256).digest()

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls(
            data_dir=Path(os.environ.get("TRIAGE_DATA_DIR", "data")),
            access_ttl=int(os.environ.get("TRIAGE_ACCESS_TTL", 15 * 60)),
            refresh_ttl=int(os.environ.get("TRIAGE_REFRESH_TTL", 7 * 24 * 3600)),
            max_upload_bytes=int(os.environ.get("TRIAGE_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)),
            transcriber=os.environ.get("TRIAGE_TRANSCRIBER", "mock"),
            classifier=os.environ.get("TRIAGE_CLASSIFIER", "rules"),
            ollama_url=os.environ.get("TRIAGE_OLLAMA_URL", "http://localhost:11434"),
            ollama_model=os.environ.get("TRIAGE_OLLAMA_MODEL", "llama3.1:8b"),
            keep_uploads=_env_bool("TRIAGE_KEEP_UPLOADS", False),
            secure_cookies=_env_bool("TRIAGE_SECURE_COOKIES", False),
        )
        s.secret_key = load_secret(s.data_dir)
        return s


def load_secret(data_dir: Path) -> bytes:
    """Use TRIAGE_SECRET_KEY, or a key file created on first run.

    The key must survive restarts: it signs tokens and the audit log, so a
    fresh random key each boot would make old audit entries unverifiable.
    """
    env = os.environ.get("TRIAGE_SECRET_KEY")
    if env:
        if len(env) < 32:
            raise SystemExit("TRIAGE_SECRET_KEY must be at least 32 characters")
        return env.encode()
    path = data_dir / "secret.key"
    if path.exists():
        return path.read_bytes().strip()
    data_dir.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    log.warning("generated a new secret key at %s; set TRIAGE_SECRET_KEY in production", path)
    return key
