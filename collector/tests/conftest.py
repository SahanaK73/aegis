import dataclasses
import http.server
import threading

import pytest

from collector.config import Config
from collector.pipeline import Collector
from collector.sender import Sender
from collector.store import Store


class FakeSaaS:
    """Real local HTTP server standing in for the SaaS ingestion endpoint."""

    def __init__(self):
        self.received = []  # list of (headers_dict, raw_body_bytes)
        self.status = 200
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n)
                outer.received.append((dict(self.headers), body))
                self.send_response(outer.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/v1/events"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def saas():
    s = FakeSaaS()
    yield s
    s.stop()


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make(tmp_path, saas, clock):
    """Factory: returns (cfg, store, collector, sender) wired to the fake SaaS."""
    made = []

    def _make(**overrides):
        cfg = dataclasses.replace(
            Config(),
            endpoint=saas.url,
            token="test-token",
            db_path=str(tmp_path / "c.db"),
            request_timeout=2.0,
            backoff_jitter=0.0,
            **overrides,
        )
        store = Store(cfg.db_path)
        made.append(store)
        return cfg, store, Collector(cfg, store, clock), Sender(cfg, store, clock)

    yield _make
    for s in made:
        try:
            s.close()
        except Exception:
            pass
