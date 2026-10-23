"""Minimal HS256 JWTs.

A production service would normally use a vetted library such as PyJWT.
This one is deliberately small and strict: the header must be exactly
{"alg": "HS256", "typ": "JWT"}, which rules out the classic "alg": "none"
and algorithm-confusion attacks by construction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_HEADER = {"alg": "HS256", "typ": "JWT"}
_HEADER_B64 = _b64e(json.dumps(_HEADER, separators=(",", ":")).encode())


def sign(claims: dict, key: bytes) -> str:
    payload = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{_HEADER_B64}.{payload}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{_HEADER_B64}.{payload}.{_b64e(sig)}"


def verify(token: str, key: bytes, *, now: float | None = None) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64d(header_b64))
        sig = _b64d(sig_b64)
    except (ValueError, json.JSONDecodeError) as e:
        raise TokenError("malformed token") from e
    if header != _HEADER:
        raise TokenError("unsupported token header")
    expected = hmac.new(key, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise TokenError("bad signature")
    try:
        claims = json.loads(_b64d(payload_b64))
    except (ValueError, json.JSONDecodeError) as e:
        raise TokenError("malformed token") from e
    if not isinstance(claims, dict) or not isinstance(claims.get("exp"), (int, float)):
        raise TokenError("token has no expiry")
    if (now if now is not None else time.time()) >= claims["exp"]:
        raise TokenError("token expired")
    return claims
