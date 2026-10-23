"""Background worker that processes queued items."""

from __future__ import annotations

import logging
import threading

from .services import ItemService

log = logging.getLogger(__name__)


class Worker(threading.Thread):
    def __init__(self, items: ItemService, poll_seconds: float = 1.0):
        super().__init__(name="triage-worker", daemon=True)
        self.items = items
        self.poll_seconds = poll_seconds
        self._stop_event = threading.Event()

    def run(self) -> None:
        recovered = self.items.recover_stuck()
        if recovered:
            log.info("requeued %d items left processing by a previous run", recovered)
        while not self._stop_event.is_set():
            try:
                worked = self.items.process_next()
            except Exception:  # never let one bad item kill the worker
                log.exception("worker error")
                worked = False
            if not worked:
                self._stop_event.wait(self.poll_seconds)

    def stop(self) -> None:
        self._stop_event.set()
