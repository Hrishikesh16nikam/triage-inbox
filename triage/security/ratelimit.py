"""In-memory token-bucket rate limiter.

Per process only: running several replicas would need a shared store such
as Redis. That limitation is listed in docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, capacity: int, per_seconds: float, *, clock=time.monotonic):
        self.capacity = float(capacity)
        self.rate = capacity / per_seconds  # tokens refilled per second
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Take one token for key. Returns (allowed, seconds until retry)."""
        with self._lock:
            now = self.clock()
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                self._prune(now)
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1 - tokens) / self.rate

    def _prune(self, now: float) -> None:
        if len(self._buckets) < 10_000:
            return
        full_after = self.capacity / self.rate
        for k, (_, last) in list(self._buckets.items()):
            if now - last > full_after:
                del self._buckets[k]
