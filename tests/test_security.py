import base64
import json
import time
import unittest

from triage.security import passwords, tokens
from triage.security.ratelimit import RateLimiter


class PasswordTests(unittest.TestCase):
    def test_round_trip(self):
        h = passwords.hash_password("correct horse battery")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(passwords.verify_password("correct horse battery", h))
        self.assertFalse(passwords.verify_password("wrong password!!", h))

    def test_salted(self):
        self.assertNotEqual(passwords.hash_password("same password here"), passwords.hash_password("same password here"))

    def test_garbage_hash_is_rejected_not_crashing(self):
        self.assertFalse(passwords.verify_password("x", "not-a-hash"))
        self.assertFalse(passwords.verify_password("x", "bcrypt$1$2$3$4$5"))

    def test_minimum_length(self):
        with self.assertRaises(ValueError):
            passwords.validate_password("short")


class TokenTests(unittest.TestCase):
    key = b"k" * 32

    def test_round_trip(self):
        t = tokens.sign({"sub": 1, "exp": time.time() + 60}, self.key)
        self.assertEqual(tokens.verify(t, self.key)["sub"], 1)

    def test_wrong_key(self):
        t = tokens.sign({"sub": 1, "exp": time.time() + 60}, self.key)
        with self.assertRaises(tokens.TokenError):
            tokens.verify(t, b"other-key" * 4)

    def test_expired(self):
        t = tokens.sign({"sub": 1, "exp": time.time() - 1}, self.key)
        with self.assertRaises(tokens.TokenError):
            tokens.verify(t, self.key)

    def test_missing_expiry(self):
        with self.assertRaises(tokens.TokenError):
            tokens.verify(tokens.sign({"sub": 1}, self.key), self.key)

    def test_tampered_payload(self):
        header, _, sig = tokens.sign({"sub": 1, "exp": time.time() + 60}, self.key).split(".")
        forged = base64.urlsafe_b64encode(json.dumps({"sub": 2, "exp": time.time() + 60}).encode()).rstrip(b"=").decode()
        with self.assertRaises(tokens.TokenError):
            tokens.verify(f"{header}.{forged}.{sig}", self.key)

    def test_alg_none_is_rejected(self):
        def b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 1, 'exp': time.time() + 60})}."
        with self.assertRaises(tokens.TokenError):
            tokens.verify(unsigned, self.key)

    def test_malformed(self):
        for bad in ("", "a.b", "a.b.c.d", "!!!.###.$$$"):
            with self.assertRaises(tokens.TokenError):
                tokens.verify(bad, self.key)


class RateLimiterTests(unittest.TestCase):
    def test_bucket_empties_and_refills(self):
        now = [0.0]
        rl = RateLimiter(3, 30, clock=lambda: now[0])  # 3 per 30 s, one token every 10 s
        self.assertTrue(all(rl.allow("ip")[0] for _ in range(3)))
        ok, retry = rl.allow("ip")
        self.assertFalse(ok)
        self.assertAlmostEqual(retry, 10, delta=0.01)
        now[0] = 10
        self.assertTrue(rl.allow("ip")[0])
        self.assertFalse(rl.allow("ip")[0])

    def test_keys_are_independent(self):
        rl = RateLimiter(1, 60)
        self.assertTrue(rl.allow("a")[0])
        self.assertTrue(rl.allow("b")[0])
        self.assertFalse(rl.allow("a")[0])
