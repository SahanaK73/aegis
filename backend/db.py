"""SQLite storage. Every query is scoped by tenant_id."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    pk INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    service_id TEXT,
    severity TEXT NOT NULL,
    event_ts REAL NOT NULL,
    timestamp_utc TEXT NOT NULL,
    received_at REAL NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL,      -- SHA-256 the BACKEND computed over the raw request bytes
    sender_sha256 TEXT NOT NULL,       -- SHA-256 the collector claimed in X-Content-SHA256
    raw_body TEXT NOT NULL,            -- the exact bytes received (UTF-8 JSON), as sent
    body TEXT NOT NULL,                -- validated event, canonical JSON (for queries)
    duplicate_deliveries INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, collector_id, event_id)
);
CREATE INDEX IF NOT EXISTS ev_tenant_recv ON events (tenant_id, received_at);
CREATE INDEX IF NOT EXISTS ev_metric ON events (tenant_id, event_type, event_ts);
CREATE TABLE IF NOT EXISTS collectors (
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    region TEXT NOT NULL,
    version TEXT,
    last_heartbeat_at REAL,
    last_telemetry_at REAL,
    cpu_percent REAL,
    memory_percent REAL,
    queue_backlog INTEGER,
    reported_state TEXT,
    first_seen_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, collector_id)
);
CREATE TABLE IF NOT EXISTS ingest_rejections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    received_at REAL NOT NULL,
    http_status INTEGER NOT NULL,
    code TEXT NOT NULL,
    sender_sha256 TEXT,
    backend_sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''     -- field names / error types only; the body is never stored
);
CREATE INDEX IF NOT EXISTS rej_tenant ON ingest_rejections (tenant_id, id);
CREATE TABLE IF NOT EXISTS aiops_snapshot (
    tenant_id TEXT PRIMARY KEY,
    updated_at REAL NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aiops_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    ts REAL NOT NULL,
    error TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    updated_at REAL NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (tenant_id, incident_id)
);
"""


class DB:
    def __init__(self, path: str):
        self._lock = threading.RLock()
        self._c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._c.close()

    def ping(self) -> bool:
        with self._lock:
            return self._c.execute("SELECT 1").fetchone()[0] == 1

    # ---- ingestion ---------------------------------------------------------
    def store_event(self, *, tenant_id: str, ev: Any, sha: str, sender_sha: str, raw_body: str,
                    body: str, now: float, late_after: float) -> tuple[str, list[str]]:
        """Returns ("accepted"|"duplicate", flags). Dedup key: tenant+collector+event_id."""
        with self._lock:
            self._c.execute("BEGIN IMMEDIATE")
            try:
                flags: list[str] = []
                if now - ev.ts_epoch > late_after:
                    flags.append("late")
                row = self._c.execute(
                    "SELECT MAX(event_ts) FROM events WHERE tenant_id=? AND collector_id=?",
                    (tenant_id, ev.collector_id),
                ).fetchone()
                if row[0] is not None and ev.ts_epoch < row[0]:
                    flags.append("out_of_order")
                cur = self._c.execute(
                    "INSERT INTO events(tenant_id, collector_id, event_id, event_type, service_id, severity, "
                    "event_ts, timestamp_utc, received_at, flags, content_sha256, sender_sha256, raw_body, body) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id, collector_id, event_id) DO NOTHING",
                    (tenant_id, ev.collector_id, ev.event_id, ev.event_type, getattr(ev, "service_id", None),
                     ev.severity, ev.ts_epoch, ev.timestamp_utc, now, ",".join(flags), sha, sender_sha,
                     raw_body, body),
                )
                if cur.rowcount == 0:
                    self._c.execute(
                        "UPDATE events SET duplicate_deliveries = duplicate_deliveries + 1 "
                        "WHERE tenant_id=? AND collector_id=? AND event_id=?",
                        (tenant_id, ev.collector_id, ev.event_id),
                    )
                    self._c.execute("COMMIT")
                    return "duplicate", []
                self._touch_collector(tenant_id, ev, now)
                self._c.execute("COMMIT")
                return "accepted", flags
            except Exception:
                self._c.execute("ROLLBACK")
                raise

    def _touch_collector(self, tenant_id: str, ev: Any, now: float) -> None:
        self._c.execute(
            "INSERT INTO collectors(tenant_id, collector_id, region, first_seen_at) VALUES(?,?,?,?) "
            "ON CONFLICT(tenant_id, collector_id) DO UPDATE SET region=excluded.region",
            (tenant_id, ev.collector_id, ev.region, now),
        )
        if ev.event_type == "heartbeat":
            self._c.execute(
                "UPDATE collectors SET last_heartbeat_at=?, version=?, cpu_percent=?, memory_percent=?, "
                "queue_backlog=?, reported_state=? WHERE tenant_id=? AND collector_id=?",
                (now, ev.collector_version, ev.cpu_percent, ev.memory_percent, ev.queue_backlog,
                 ev.health_state, tenant_id, ev.collector_id),
            )
        else:
            self._c.execute(
                "UPDATE collectors SET last_telemetry_at=? WHERE tenant_id=? AND collector_id=?",
                (now, tenant_id, ev.collector_id),
            )

    # ---- reads (always tenant-scoped) ---------------------------------------
    def recent_events(self, tenant_id: str, limit: int, collector_id: str | None,
                      event_type: str | None) -> list[dict]:
        q = "SELECT * FROM events WHERE tenant_id=?"
        args: list[Any] = [tenant_id]
        if collector_id:
            q += " AND collector_id=?"; args.append(collector_id)
        if event_type:
            q += " AND event_type=?"; args.append(event_type)
        q += " ORDER BY pk DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._c.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def collectors(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = self._c.execute(
                "SELECT * FROM collectors WHERE tenant_id=? ORDER BY collector_id", (tenant_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def metrics_since(self, tenant_id: str, since_received: float) -> list[dict]:
        with self._lock:
            rows = self._c.execute(
                "SELECT service_id, severity, timestamp_utc, event_ts, body FROM events "
                "WHERE tenant_id=? AND event_type='metric' AND received_at>=? ORDER BY event_ts DESC, pk DESC",
                (tenant_id, since_received),
            ).fetchall()
        return [dict(r) for r in rows]

    def count_events(self, tenant_id: str) -> int:
        with self._lock:
            return self._c.execute("SELECT COUNT(*) FROM events WHERE tenant_id=?", (tenant_id,)).fetchone()[0]

    # ---- incidents ----------------------------------------------------------
    def upsert_incident(self, tenant_id: str, incident_id: str, body: dict, now: float) -> None:
        with self._lock:
            self._c.execute(
                "INSERT INTO incidents(tenant_id, incident_id, updated_at, body) VALUES(?,?,?,?) "
                "ON CONFLICT(tenant_id, incident_id) DO UPDATE SET updated_at=excluded.updated_at, body=excluded.body",
                (tenant_id, incident_id, now, json.dumps(body, sort_keys=True)),
            )

    def incidents(self, tenant_id: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._c.execute(
                "SELECT updated_at, body FROM incidents WHERE tenant_id=? ORDER BY updated_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [{**json.loads(r["body"]), "updated_at": r["updated_at"]} for r in rows]

    # ---- egress evidence: rejections ----------------------------------------
    def record_rejection(self, *, tenant_id: str, now: float, http_status: int, code: str,
                         sender_sha: str | None, backend_sha: str, size: int, detail: str = "") -> None:
        with self._lock:
            self._c.execute(
                "INSERT INTO ingest_rejections(tenant_id, received_at, http_status, code, sender_sha256, "
                "backend_sha256, size, detail) VALUES(?,?,?,?,?,?,?,?)",
                (tenant_id, now, http_status, code, sender_sha, backend_sha, size, detail[:300]),
            )

    def recent_rejections(self, tenant_id: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._c.execute(
                "SELECT * FROM ingest_rejections WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def count_rejections(self, tenant_id: str) -> int:
        with self._lock:
            return self._c.execute(
                "SELECT COUNT(*) FROM ingest_rejections WHERE tenant_id=?", (tenant_id,)).fetchone()[0]

    def duplicate_total(self, tenant_id: str) -> int:
        with self._lock:
            return self._c.execute(
                "SELECT COALESCE(SUM(duplicate_deliveries),0) FROM events WHERE tenant_id=?",
                (tenant_id,)).fetchone()[0]

    # ---- AIOps support ------------------------------------------------------
    def events_for_aiops(self, tenant_id: str, limit: int) -> list[dict]:
        """Most recent `limit` stored events, oldest first, parsed."""
        with self._lock:
            rows = self._c.execute(
                "SELECT body FROM events WHERE tenant_id=? ORDER BY pk DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        return [json.loads(r["body"]) for r in reversed(rows)]

    def save_snapshot(self, tenant_id: str, body: dict, now: float) -> None:
        with self._lock:
            self._c.execute(
                "INSERT INTO aiops_snapshot(tenant_id, updated_at, body) VALUES(?,?,?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET updated_at=excluded.updated_at, body=excluded.body",
                (tenant_id, now, json.dumps(body, sort_keys=True)),
            )

    def load_snapshot(self, tenant_id: str) -> dict | None:
        with self._lock:
            r = self._c.execute("SELECT updated_at, body FROM aiops_snapshot WHERE tenant_id=?",
                                (tenant_id,)).fetchone()
        return {**json.loads(r["body"]), "updated_at": r["updated_at"]} if r else None

    def add_aiops_error(self, tenant_id: str, now: float, error: str) -> None:
        with self._lock:
            self._c.execute("INSERT INTO aiops_errors(tenant_id, ts, error) VALUES(?,?,?)",
                            (tenant_id, now, error[:500]))

    def aiops_errors(self, tenant_id: str, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._c.execute("SELECT ts, error FROM aiops_errors WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                                   (tenant_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def all_incident_bodies(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = self._c.execute("SELECT body FROM incidents WHERE tenant_id=?", (tenant_id,)).fetchall()
        return [json.loads(r["body"]) for r in rows]
