import dataclasses
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app

NOW = 1_800_000_000.0
TOKEN_A, TOKEN_B = "dev-token-tenant-a", "dev-token-tenant-b"


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def iso(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def body_of(ev: dict) -> bytes:
    return json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()


def metric(n=1, t=NOW, **kw):
    ev = {"event_id": f"evt-{n:06d}", "collector_id": "collector-001", "event_type": "metric",
          "service_id": "payment-api", "timestamp_utc": iso(t), "source_timezone": "Asia/Kolkata",
          "region": "ap-south", "severity": "info", "policy_version": "v1",
          "metric_name": "cpu_usage", "metric_value": 42.5, "unit": "percent",
          "health_scope": "infrastructure", "window_seconds": 2}
    ev.update(kw)
    return ev


def heartbeat(n=2, t=NOW, **kw):
    ev = {"event_id": f"evt-{n:06d}", "collector_id": "collector-001", "event_type": "heartbeat",
          "timestamp_utc": iso(t), "source_timezone": "Asia/Kolkata", "region": "ap-south",
          "severity": "info", "policy_version": "v1", "health_scope": "collector",
          "health_state": "excellent", "collector_version": "0.1.0", "queue_backlog": 0}
    ev.update(kw)
    return ev


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def client(tmp_path, clock):
    cfg = dataclasses.replace(Settings(), db_path=str(tmp_path / "b.db"), aiops_mode="sync")
    app = create_app(cfg, clock)
    with TestClient(app) as c:
        yield c


def post(client, ev, token=TOKEN_A, raw=None, sha=None):
    raw = raw if raw is not None else body_of(ev)
    headers = {"X-Content-SHA256": sha or hashlib.sha256(raw).hexdigest(), "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post("/api/v1/events", content=raw, headers=headers)


def auth(token=TOKEN_A):
    return {"Authorization": f"Bearer {token}"}
