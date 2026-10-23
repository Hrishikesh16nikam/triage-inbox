"""Password hashing with scrypt, a memory-hard KDF from the standard library.

Stored format: scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
Parameters live in the hash, so they can be raised later without breaking
existing users (see needs_rehash).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

N, R, P = 2**14, 8, 1
DKLEN = 32
MIN_LENGTH = 12


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=DKLEN, maxmem=64 * 1024 * 1024)


def validate_password(password: str) -> None:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    if len(password) > 256:
        raise ValueError("password is too long")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(_derive(password, salt, N, R, P))}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        actual = _derive(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, base64.b64decode(expected))


def needs_rehash(stored: str) -> bool:
    return not stored.startswith(f"scrypt${N}${R}${P}$")


# Verified against when a username doesn't exist, so a failed login takes
# the same time either way and can't be used to discover valid usernames.
DUMMY_HASH = hash_password("dummy-password-for-timing")
