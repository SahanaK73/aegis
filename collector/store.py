"""SQLite persistence: outbox, tamper-evident audit chain, local raw logs, violations.

Outbox rule: write BEFORE send, delete only on acknowledged delivery.
Audit chain: every record's hash covers the previous record's hash, so editing or
deleting a past row breaks verification from that point on.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass

GENESIS = "0" * 64


@dataclass(frozen=True)
class OutboxRow:
    event_id: str
    seq: int
    payload: bytes
    sha256: str
    attempts: int
    next_attempt_at: float


SCHEMA = """
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (
    event_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    payload BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    created_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_attempt_at, seq);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    event_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    expires_at REAL NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    reason TEXT NOT NULL,
    fields TEXT NOT NULL DEFAULT ''
);
"""


def _record_hash(prev: str, ts: float, kind: str, event_id: str, sha: str, size: int) -> str:
    material = f"{prev}|{ts!r}|{kind}|{event_id}|{sha}|{size}".encode()
    return hashlib.sha256(material).hexdigest()


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- ids ---------------------------------------------------------------
    def allocate_event_id(self) -> tuple[str, int]:
        """Durably allocate the next event id. Never reused, even across restarts."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT value FROM state WHERE key='seq'").fetchone()
                seq = (row[0] if row else 0) + 1
                self._conn.execute(
                    "INSERT INTO state(key, value) VALUES('seq', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (seq,),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            return f"evt-{seq:06d}", seq

    # ---- outbox ------------------------------------------------------------
    def _append_audit(self, ts: float, kind: str, event_id: str, sha: str, size: int) -> None:
        row = self._conn.execute("SELECT record_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        rh = _record_hash(prev, ts, kind, event_id, sha, size)
        self._conn.execute(
            "INSERT INTO audit(ts, kind, event_id, sha256, size, prev_hash, record_hash) "
            "VALUES(?,?,?,?,?,?,?)",
            (ts, kind, event_id, sha, size, prev, rh),
        )

    def enqueue(self, event_id: str, seq: int, payload: bytes, sha: str, now: float) -> None:
        """Atomically persist the event and its audit record before any send."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO outbox(event_id, seq, payload, sha256, created_at, attempts, next_attempt_at) "
                    "VALUES(?,?,?,?,?,0,?)",
                    (event_id, seq, payload, sha, now, now),
                )
                self._append_audit(now, "prepared", event_id, sha, len(payload))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def due(self, now: float, limit: int) -> list[OutboxRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id, seq, payload, sha256, attempts, next_attempt_at FROM outbox "
                "WHERE next_attempt_at <= ? ORDER BY seq LIMIT ?",
                (now, limit),
            ).fetchall()
        return [OutboxRow(r[0], r[1], bytes(r[2]), r[3], r[4], r[5]) for r in rows]

    def get(self, event_id: str) -> OutboxRow | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT event_id, seq, payload, sha256, attempts, next_attempt_at FROM outbox WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return OutboxRow(r[0], r[1], bytes(r[2]), r[3], r[4], r[5]) if r else None

    def mark_failed(self, event_id: str, next_attempt_at: float) -> None:
        """Keep the event (same event_id, same bytes) and schedule a later retry."""
        with self._lock:
            self._conn.execute(
                "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ? WHERE event_id = ?",
                (next_attempt_at, event_id),
            )

    def ack(self, event_id: str, now: float) -> bool:
        """Delete from the outbox ONLY after the server acknowledged."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT sha256, length(payload) FROM outbox WHERE event_id=?", (event_id,)
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return False
                self._conn.execute("DELETE FROM outbox WHERE event_id=?", (event_id,))
                self._append_audit(now, "acked", event_id, row[0], row[1])
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def backlog(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    # ---- audit -------------------------------------------------------------
    def audit_records(self) -> list[tuple]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, ts, kind, event_id, sha256, size, prev_hash, record_hash FROM audit ORDER BY id"
            ).fetchall()

    def verify_audit_chain(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_id). Any edit or deletion breaks the chain."""
        prev = GENESIS
        for rid, ts, kind, event_id, sha, size, prev_hash, rh in self.audit_records():
            if prev_hash != prev or rh != _record_hash(prev, ts, kind, event_id, sha, size):
                return False, rid
            prev = rh
        return True, None

    # ---- raw local logs (never leave the environment) ----------------------
    def add_raw(self, ts: float, text: str, retention_seconds: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO raw_logs(ts, expires_at, text) VALUES(?,?,?)",
                (ts, ts + retention_seconds, text),
            )

    def purge_raw(self, now: float) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM raw_logs WHERE expires_at <= ?", (now,))
            return cur.rowcount

    def raw_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]

    # ---- violations (names/categories only, never values) ------------------
    def add_violation(self, ts: float, reason: str, fields: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO violations(ts, reason, fields) VALUES(?,?,?)", (ts, reason, fields)
            )

    def violations(self) -> list[tuple]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, ts, reason, fields FROM violations ORDER BY id"
            ).fetchall()
