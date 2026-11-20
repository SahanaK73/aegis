"""PostgreSQL storage. Every query is scoped by tenant_id."""

from __future__ import annotations

import json
import threading
from typing import Any

import psycopg2
import psycopg2.extras

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    pk SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    service_id TEXT,
    severity TEXT NOT NULL,
    event_ts DOUBLE PRECISION NOT NULL,
    timestamp_utc TEXT NOT NULL,
    received_at DOUBLE PRECISION NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL,
    sender_sha256 TEXT NOT NULL,
    raw_body TEXT NOT NULL,
    body TEXT NOT NULL,
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
    last_heartbeat_at DOUBLE PRECISION,
    last_telemetry_at DOUBLE PRECISION,
    cpu_percent DOUBLE PRECISION,
    memory_percent DOUBLE PRECISION,
    queue_backlog INTEGER,
    reported_state TEXT,
    first_seen_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, collector_id)
);

CREATE TABLE IF NOT EXISTS ingest_rejections (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    received_at DOUBLE PRECISION NOT NULL,
    http_status INTEGER NOT NULL,
    code TEXT NOT NULL,
    sender_sha256 TEXT,
    backend_sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS rej_tenant ON ingest_rejections (tenant_id, id);

CREATE TABLE IF NOT EXISTS aiops_snapshot (
    tenant_id TEXT PRIMARY KEY,
    updated_at DOUBLE PRECISION NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS aiops_errors (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ts DOUBLE PRECISION NOT NULL,
    error TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (tenant_id, incident_id)
);
"""


class DB:
    def __init__(self, dsn: str):
        self._lock = threading.RLock()
        self._dsn = dsn
        self._conn = psycopg2.connect(dsn)
        self._conn.autocommit = True
        with self._conn.cursor() as cur:
            for stmt in SCHEMA.strip().split(';'):
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)

    def _cur(self):
        return self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ping(self) -> bool:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT 1 AS ok")
                return cur.fetchone()["ok"] == 1

    # ---- ingestion ---------------------------------------------------------
    def store_event(self, *, tenant_id: str, ev: Any, sha: str, sender_sha: str, raw_body: str,
                    body: str, now: float, late_after: float) -> tuple[str, list[str]]:
        """Returns ('accepted'|'duplicate', flags). Dedup key: tenant+collector+event_id."""
        with self._lock:
            old_autocommit = self._conn.autocommit
            self._conn.autocommit = False
            try:
                with self._cur() as cur:
                    flags: list[str] = []
                    if now - ev.ts_epoch > late_after:
                        flags.append("late")
                    cur.execute(
                        "SELECT MAX(event_ts) AS max_ts FROM events WHERE tenant_id=%s AND collector_id=%s",
                        (tenant_id, ev.collector_id),
                    )
                    row = cur.fetchone()
                    if row["max_ts"] is not None and ev.ts_epoch < row["max_ts"]:
                        flags.append("out_of_order")
                    cur.execute(
                        "INSERT INTO events(tenant_id, collector_id, event_id, event_type, service_id, severity, "
                        "event_ts, timestamp_utc, received_at, flags, content_sha256, sender_sha256, raw_body, body) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                        "ON CONFLICT(tenant_id, collector_id, event_id) DO NOTHING",
                        (tenant_id, ev.collector_id, ev.event_id, ev.event_type, getattr(ev, "service_id", None),
                         ev.severity, ev.ts_epoch, ev.timestamp_utc, now, ",".join(flags), sha, sender_sha,
                         raw_body, body),
                    )
                    if cur.rowcount == 0:
                        cur.execute(
                            "UPDATE events SET duplicate_deliveries = duplicate_deliveries + 1 "
                            "WHERE tenant_id=%s AND collector_id=%s AND event_id=%s",
                            (tenant_id, ev.collector_id, ev.event_id),
                        )
                        self._conn.commit()
                        return "duplicate", []
                    self._touch_collector(tenant_id, ev, now, cur)
                    self._conn.commit()
                    return "accepted", flags
            except Exception:
                self._conn.rollback()
                raise
            finally:
                self._conn.autocommit = old_autocommit

    def _touch_collector(self, tenant_id: str, ev: Any, now: float, cur: Any) -> None:
        cur.execute(
            "INSERT INTO collectors(tenant_id, collector_id, region, first_seen_at) VALUES(%s,%s,%s,%s) "
            "ON CONFLICT(tenant_id, collector_id) DO UPDATE SET region=EXCLUDED.region",
            (tenant_id, ev.collector_id, ev.region, now),
        )
        if ev.event_type == "heartbeat":
            cur.execute(
                "UPDATE collectors SET last_heartbeat_at=%s, version=%s, cpu_percent=%s, memory_percent=%s, "
                "queue_backlog=%s, reported_state=%s WHERE tenant_id=%s AND collector_id=%s",
                (now, ev.collector_version, ev.cpu_percent, ev.memory_percent, ev.queue_backlog,
                 ev.health_state, tenant_id, ev.collector_id),
            )
        else:
            cur.execute(
                "UPDATE collectors SET last_telemetry_at=%s WHERE tenant_id=%s AND collector_id=%s",
                (now, tenant_id, ev.collector_id),
            )

    # ---- reads (always tenant-scoped) ---------------------------------------
    def recent_events(self, tenant_id: str, limit: int, collector_id: str | None = None,
                      event_type: str | None = None) -> list[dict]:
        q = "SELECT * FROM events WHERE tenant_id=%s"
        args: list[Any] = [tenant_id]
        if collector_id:
            q += " AND collector_id=%s"
            args.append(collector_id)
        if event_type:
            q += " AND event_type=%s"
            args.append(event_type)
        q += " ORDER BY pk DESC LIMIT %s"
        args.append(limit)
        with self._lock:
            with self._cur() as cur:
                cur.execute(q, args)
                return [dict(r) for r in cur.fetchall()]

    def collectors(self, tenant_id: str) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT * FROM collectors WHERE tenant_id=%s ORDER BY collector_id", (tenant_id,)
                )
                return [dict(r) for r in cur.fetchall()]

    def metrics_since(self, tenant_id: str, since_received: float) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT service_id, severity, timestamp_utc, event_ts, body FROM events "
                    "WHERE tenant_id=%s AND event_type='metric' AND received_at>=%s ORDER BY event_ts DESC, pk DESC",
                    (tenant_id, since_received),
                )
                return [dict(r) for r in cur.fetchall()]

    def count_events(self, tenant_id: str) -> int:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT COUNT(*) AS cnt FROM events WHERE tenant_id=%s", (tenant_id,))
                return cur.fetchone()["cnt"]

    # ---- incidents ----------------------------------------------------------
    def upsert_incident(self, tenant_id: str, incident_id: str, body: dict, now: float) -> None:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "INSERT INTO incidents(tenant_id, incident_id, updated_at, body) VALUES(%s,%s,%s,%s) "
                    "ON CONFLICT(tenant_id, incident_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, body=EXCLUDED.body",
                    (tenant_id, incident_id, now, json.dumps(body, sort_keys=True)),
                )

    def incidents(self, tenant_id: str, limit: int) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT updated_at, body FROM incidents WHERE tenant_id=%s ORDER BY updated_at DESC LIMIT %s",
                    (tenant_id, limit),
                )
                rows = cur.fetchall()
        return [{**json.loads(r["body"]), "updated_at": r["updated_at"]} for r in rows]

    # ---- egress evidence: rejections ----------------------------------------
    def record_rejection(self, *, tenant_id: str, now: float, http_status: int, code: str,
                         sender_sha: str | None, backend_sha: str, size: int, detail: str = "") -> None:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "INSERT INTO ingest_rejections(tenant_id, received_at, http_status, code, sender_sha256, "
                    "backend_sha256, size, detail) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (tenant_id, now, http_status, code, sender_sha, backend_sha, size, detail[:300]),
                )

    def recent_rejections(self, tenant_id: str, limit: int) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT * FROM ingest_rejections WHERE tenant_id=%s ORDER BY id DESC LIMIT %s", (tenant_id, limit)
                )
                return [dict(r) for r in cur.fetchall()]

    def count_rejections(self, tenant_id: str) -> int:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT COUNT(*) AS cnt FROM ingest_rejections WHERE tenant_id=%s", (tenant_id,))
                return cur.fetchone()["cnt"]

    def duplicate_total(self, tenant_id: str) -> int:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT COALESCE(SUM(duplicate_deliveries),0) AS total FROM events WHERE tenant_id=%s",
                    (tenant_id,))
                return cur.fetchone()["total"]

    # ---- AIOps support ------------------------------------------------------
    def events_for_aiops(self, tenant_id: str, limit: int) -> list[dict]:
        """Most recent `limit` stored events, oldest first, parsed."""
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "SELECT body FROM events WHERE tenant_id=%s ORDER BY pk DESC LIMIT %s", (tenant_id, limit)
                )
                rows = cur.fetchall()
        return [json.loads(r["body"]) for r in reversed(rows)]

    def save_snapshot(self, tenant_id: str, body: dict, now: float) -> None:
        with self._lock:
            with self._cur() as cur:
                cur.execute(
                    "INSERT INTO aiops_snapshot(tenant_id, updated_at, body) VALUES(%s,%s,%s) "
                    "ON CONFLICT(tenant_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, body=EXCLUDED.body",
                    (tenant_id, now, json.dumps(body, sort_keys=True)),
                )

    def load_snapshot(self, tenant_id: str) -> dict | None:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT updated_at, body FROM aiops_snapshot WHERE tenant_id=%s",
                            (tenant_id,))
                r = cur.fetchone()
        return {**json.loads(r["body"]), "updated_at": r["updated_at"]} if r else None

    def add_aiops_error(self, tenant_id: str, now: float, error: str) -> None:
        with self._lock:
            with self._cur() as cur:
                cur.execute("INSERT INTO aiops_errors(tenant_id, ts, error) VALUES(%s,%s,%s)",
                            (tenant_id, now, error[:500]))

    def aiops_errors(self, tenant_id: str, limit: int = 20) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT ts, error FROM aiops_errors WHERE tenant_id=%s ORDER BY id DESC LIMIT %s",
                            (tenant_id, limit))
                return [dict(r) for r in cur.fetchall()]

    def all_incident_bodies(self, tenant_id: str) -> list[dict]:
        with self._lock:
            with self._cur() as cur:
                cur.execute("SELECT body FROM incidents WHERE tenant_id=%s", (tenant_id,))
                return [json.loads(r["body"]) for r in cur.fetchall()]
