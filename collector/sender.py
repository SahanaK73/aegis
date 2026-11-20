"""Sender: POST the exact stored bytes, ack => delete, failure => keep and back off.

The body sent is the stored payload bytes (never re-serialized), and the SHA-256 of
those same bytes goes in the X-Content-SHA256 header. Retries re-send the same
bytes with the same event_id, so the server can deduplicate.
"""

from __future__ import annotations

import random
import time
from typing import Callable

import requests

from .config import Config
from .egress import HASH_HEADER
from .store import Store

# 2xx = accepted. 409 = server already has this event_id (duplicate) -> also an ack.
ACK_STATUSES = {409}


def is_ack(status: int) -> bool:
    return 200 <= status < 300 or status in ACK_STATUSES


class Sender:
    def __init__(self, config: Config, store: Store, now_fn: Callable[[], float] = time.time):
        self.config = config
        self.store = store
        self.now = now_fn
        self.session = requests.Session()
        self.consecutive_failures = 0
        self.last_ack_at: float | None = None

    def _backoff(self, attempts: int) -> float:
        c = self.config
        base = min(c.backoff_max, c.backoff_base * (2 ** attempts))
        return base * (1 + random.uniform(-c.backoff_jitter, c.backoff_jitter))

    def _headers(self, sha: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
            "X-Collector-Id": self.config.collector_id,
            HASH_HEADER: sha,
        }

    def drain(self) -> dict[str, int]:
        """Send everything that is due, oldest first. Stops at the first failure."""
        result = {"sent": 0, "failed": 0}
        for row in self.store.due(self.now(), self.config.batch_size):
            try:
                resp = self.session.post(
                    self.config.endpoint,
                    data=row.payload,
                    headers=self._headers(row.sha256),
                    timeout=self.config.request_timeout,
                )
                status = resp.status_code
            except requests.RequestException:
                status = 0
            if is_ack(status):
                self.store.ack(row.event_id, self.now())
                self.consecutive_failures = 0
                self.last_ack_at = self.now()
                result["sent"] += 1
            else:
                self.store.mark_failed(row.event_id, self.now() + self._backoff(row.attempts))
                self.consecutive_failures += 1
                result["failed"] += 1
                break  # keep ordering; retry the oldest first on the next cycle
        return result
