"""Real components wired together for integration tests.

Backend: the real FastAPI app served by uvicorn on a real TCP port (own thread).
Collector: the real Collector/Store/Sender classes talking to it over real HTTP.
AIOps: the real worker inside the backend. One shared fake clock keeps runs fast and deterministic.
"""

from __future__ import annotations

import dataclasses
import random
import socket
import threading
import time

import requests
import uvicorn

from backend.config import Settings
from backend.main import create_app
from collector.config import Config
from collector.pipeline import Collector
from collector.sender import Sender
from collector.simulator import records_for_tick
from collector.store import Store

TOKEN_A, TOKEN_B = "dev-token-tenant-a", "dev-token-tenant-b"


class Clock:
    def __init__(self, t: float | None = None):
        self.t = float(int(t if t is not None else time.time()))

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendServer:
    def __init__(self, db_path: str, clock: Clock, port: int | None = None, aiops_mode: str = "background"):
        self.db_path, self.clock = db_path, clock
        self.port = port or free_port()
        self.aiops_mode = aiops_mode
        self.app = None
        self.server = None
        self.thread = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "BackendServer":
        cfg = dataclasses.replace(Settings(), db_path=self.db_path, aiops_mode=self.aiops_mode,
                                  aiops_min_interval_seconds=0.05)
        self.app = create_app(cfg, self.clock)
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("backend did not start")

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True
            self.thread.join(timeout=10)
            self.app.state.db.close()
            self.server = None

    def flush_aiops(self) -> None:
        assert self.app.state.aiops.flush(15), "AIOps worker did not go idle"

    # convenience GET with a tenant token
    def get(self, path: str, token: str = TOKEN_A, **params):
        return requests.get(self.url + path, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=5)


class CollectorRig:
    """A real collector pointed at the backend, driven tick by tick."""

    def __init__(self, tmp_path, url: str, clock: Clock, token: str = TOKEN_A, **overrides):
        self.clock = clock
        self.cfg = dataclasses.replace(Config(), endpoint=url + "/api/v1/events", token=token,
                                       db_path=str(tmp_path / "collector.db"), request_timeout=2.0,
                                       backoff_jitter=0.0, backoff_base=1.0, backoff_max=4.0, **overrides)
        self.store = Store(self.cfg.db_path)
        self.collector = Collector(self.cfg, self.store, clock)
        self.sender = Sender(self.cfg, self.store, clock)
        self.rng = random.Random(7)
        self.tick_no = 0
        self.emitted: list[str] = []

    def tick(self, scenario: str, send: bool = True, step: float = 2.0) -> None:
        for rec in records_for_tick(scenario, self.tick_no, self.rng):
            self.emitted += self.collector.ingest(rec)
        self.collector.tick()
        hb = self.collector.heartbeat(self.sender.consecutive_failures)
        if hb:
            self.emitted.append(hb)
        if send:
            self.drain()
        self.tick_no += 1
        self.clock.advance(step)

    def drain(self, max_rounds: int = 200) -> None:
        for _ in range(max_rounds):
            if self.store.backlog() == 0:
                return
            res = self.sender.drain()
            if res["failed"]:
                return

    def close(self) -> None:
        self.store.close()
