"""Validate uploads before they touch the disk or the pipeline."""

from __future__ import annotations

import re
import unicodedata

from .errors import ApiError

ALLOWED = {
    ".wav": "audio",
    ".mp3": "audio",
    ".m4a": "audio",
    ".txt": "document",
    ".md": "document",
}


def safe_display_name(name: str) -> str:
    """Keep only a harmless basename for display. Files are stored under a
    random ID, never under this name, so path tricks can't reach the disk."""
    name = re.split(r"[\\/]", name or "")[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip()
    return name[:120] or "upload"


def extension(name: str) -> str:
    dot = name.rfind(".")
    return name[dot:].lower() if dot != -1 else ""


def _looks_like(ext: str, data: bytes) -> bool:
    if ext == ".wav":
        return data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    if ext == ".mp3":
        return data[:3] == b"ID3" or (len(data) > 1 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0)
    if ext == ".m4a":
        return data[4:8] == b"ftyp"
    if ext in (".txt", ".md"):
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return False


def validate_upload(filename: str, data: bytes, max_bytes: int) -> tuple[str, str]:
    """Return (display_name, kind) or raise ApiError."""
    display = safe_display_name(filename)
    ext = extension(display)
    if ext not in ALLOWED:
        raise ApiError(415, f"unsupported file type; allowed: {', '.join(sorted(ALLOWED))}")
    if not data:
        raise ApiError(400, "file is empty")
    if len(data) > max_bytes:
        raise ApiError(413, f"file is larger than {max_bytes // (1024 * 1024)} MB")
    # Check the content, not just the name: a renamed executable is rejected.
    if not _looks_like(ext, data):
        raise ApiError(415, f"file content does not match its {ext} extension")
    return display, ALLOWED[ext]
