"""Collector pipeline: raw record -> local store / candidate -> policy gate -> outbox.

Raw records (free text, usernames, IPs, secrets) stay in the local SQLite raw_logs
table. Only structured candidates built here can reach the outbox, and every one of
them passes enforce_allowlist() and validate_outbound() first.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from .config import Config
from .egress import serialize_event, sha256_hex
from .policy import PolicyViolation, enforce_allowlist, validate_outbound
from .redaction import redact
from .store import Store


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuthFailureAggregator:
    """Counts failed logins per service. Raw records are never forwarded.

    Emits an EARLY summary the moment the threshold is crossed (so the alert does not
    wait for the window to close) and a FINAL summary when the window closes.
    """

    def __init__(self, window_seconds: int, threshold: int):
        self.window = window_seconds
        self.threshold = threshold
        self._state: dict[str, dict[str, Any]] = {}

    def record_failure(self, service_id: str, now: float) -> list[tuple[str, int]]:
        """Returns summaries to emit now: list of (service_id, failure_count)."""
        out: list[tuple[str, int]] = []
        st = self._state.setdefault(service_id, {"start": now, "count": 0, "early": False})
        if now - st["start"] >= self.window:
            out.extend(self._close(service_id))
            st = self._state.setdefault(service_id, {"start": now, "count": 0, "early": False})
        st["count"] += 1
        if st["count"] >= self.threshold and not st["early"]:
            st["early"] = True
            out.append((service_id, st["count"]))
        return out

    def flush(self, now: float) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for service_id in list(self._state):
            if now - self._state[service_id]["start"] >= self.window:
                out.extend(self._close(service_id))
        return out

    def _close(self, service_id: str) -> list[tuple[str, int]]:
        st = self._state.pop(service_id)
        return [(service_id, st["count"])] if st["count"] >= self.threshold else []


class Collector:
    def __init__(self, config: Config, store: Store, now_fn: Callable[[], float] = time.time):
        self.config = config
        self.store = store
        self.now = now_fn
        self.auth = AuthFailureAggregator(config.auth_window_seconds, config.auth_threshold)
        self.stats = {"emitted": 0, "blocked": 0, "dropped_fields": 0}

    # ---- the single gate every outbound event goes through ----------------
    def emit(self, candidate: dict[str, Any]) -> str | None:
        """Fill envelope, drop non-allow-listed fields, validate, persist to outbox.

        Returns the event_id, or None if blocked (violation recorded, nothing queued).
        """
        now = self.now()
        event_id, seq = self.store.allocate_event_id()
        envelope = {
            "event_id": event_id,
            "collector_id": self.config.collector_id,
            "timestamp_utc": iso_utc(now),
            "source_timezone": self.config.source_timezone,
            "region": self.config.region,
            "policy_version": self.config.policy_version,
        }
        merged = {**envelope, **candidate}
        # Envelope identity fields cannot be overridden by the caller.
        for k in ("event_id", "collector_id", "policy_version"):
            merged[k] = envelope[k]
        merged.setdefault("severity", "info")
        try:
            clean, dropped = enforce_allowlist(merged)
            if dropped:
                self.stats["dropped_fields"] += len(dropped)
                self.store.add_violation(now, "fields_dropped", ",".join(dropped))
            validate_outbound(clean)
            payload = serialize_event(clean)
        except PolicyViolation as exc:
            self.stats["blocked"] += 1
            self.store.add_violation(now, f"blocked: {exc}")
            return None
        self.store.enqueue(event_id, seq, payload, sha256_hex(payload), now)
        self.stats["emitted"] += 1
        return event_id

    # ---- ingestion ---------------------------------------------------------
    def ingest(self, record: dict[str, Any]) -> list[str]:
        """Handle one raw record from the simulator or a real adapter."""
        now = self.now()
        kind = record.get("kind")
        emitted: list[str | None] = []

        raw_line = record.get("raw_line")
        if isinstance(raw_line, str):
            # Raw text is kept locally only, for the configured retention period.
            self.store.add_raw(now, raw_line, self.config.raw_retention_seconds)

        if kind == "metric":
            emitted.append(
                self.emit(
                    {
                        "event_type": "metric",
                        "service_id": record["service_id"],
                        "metric_name": record["metric_name"],
                        "metric_value": record["value"],
                        "unit": record["unit"],
                        "severity": record.get("severity", "info"),
                        "health_scope": "infrastructure",
                        "window_seconds": int(self.config.tick_seconds) or 1,
                    }
                )
            )
        elif kind == "auth":
            if record.get("outcome") == "failure":
                for service_id, count in self.auth.record_failure(record["service_id"], now):
                    emitted.append(self._emit_auth_summary(service_id, count))
        else:
            self.store.add_violation(now, "unknown_record_kind")

        return [e for e in emitted if e]

    def tick(self) -> list[str]:
        """Periodic housekeeping: close auth windows, purge expired raw logs."""
        now = self.now()
        out = [self._emit_auth_summary(s, c) for s, c in self.auth.flush(now)]
        self.store.purge_raw(now)
        return [e for e in out if e]

    def _emit_auth_summary(self, service_id: str, count: int) -> str | None:
        return self.emit(
            {
                "event_type": "auth_failure_summary",
                "service_id": service_id,
                "failure_count": count,
                "window_seconds": self.config.auth_window_seconds,
                "summary_code": "REPEATED_AUTH_FAILURE",
                "severity": "high",
            }
        )

    # ---- heartbeat ---------------------------------------------------------
    def collector_health(self, consecutive_send_failures: int) -> str:
        backlog = self.store.backlog()
        if consecutive_send_failures >= 5 or backlog > 500:
            return "poor"
        if consecutive_send_failures >= 2 or backlog > 100:
            return "fair"
        if consecutive_send_failures == 1 or backlog > 10:
            return "good"
        return "excellent"

    def heartbeat(self, consecutive_send_failures: int = 0) -> str | None:
        return self.emit(
            {
                "event_type": "heartbeat",
                "health_scope": "collector",
                "health_state": self.collector_health(consecutive_send_failures),
                "collector_version": self.config.collector_version,
                "queue_backlog": self.store.backlog(),
                "severity": "info",
            }
        )

    @staticmethod
    def redact_preview(text: str) -> tuple[str, dict[str, int]]:
        """Local-only helper (e.g. for a local UI). Not used on the outbound path."""
        return redact(text)
