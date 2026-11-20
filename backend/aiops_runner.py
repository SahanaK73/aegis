"""Connects accepted backend events to the deterministic AIOps engine.

Design (simple on purpose): after an event is stored, the ingest handler calls
`notify(tenant_id)` and returns. A single worker thread then re-runs the existing
AegisAIOpsPipeline over that tenant's recent stored events (batch API, deterministic,
rolling baselines rebuilt from stored history) and saves the result:

  - incidents     -> `incidents` table with STABLE ids (a re-run updates, never duplicates)
  - anomalies +   -> `aiops_snapshot`
    dependency graph
  - failures      -> `aiops_errors` (the accepted event is never lost or rolled back)

Modes: "background" (default), "sync" (inline, for tests), "off".
"""

from __future__ import annotations

import re
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable

from aiops.adapter import normalize_event
from aiops.anomaly_detector import parse_utc_timestamp
from aiops.config import AIOpsConfig
from aiops.pipeline import AegisAIOpsPipeline

from .config import Settings
from .db import DB


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AIOpsRunner:
    def __init__(self, db: DB, cfg: Settings, clock: Callable[[], float] = time.time):
        self.db, self.cfg, self.clock = db, cfg, clock
        self.mode = cfg.aiops_mode
        self._pending: set[str] = set()
        self._cv = threading.Condition()
        self._running = False
        self._stop = False
        self._thread: threading.Thread | None = None
        self.runs = 0
        if self.mode == "background":
            self._thread = threading.Thread(target=self._loop, name="aiops-worker", daemon=True)
            self._thread.start()

    # ---- public --------------------------------------------------------------
    def notify(self, tenant_id: str) -> None:
        if self.mode == "off":
            return
        if self.mode == "sync":
            self.run_tenant(tenant_id)
            return
        with self._cv:
            self._pending.add(tenant_id)
            self._cv.notify()

    def refresh(self, tenant_id: str) -> None:
        """Run now (used by tests and by a stale-heartbeat check)."""
        self.run_tenant(tenant_id)

    def flush(self, timeout: float = 10.0) -> bool:
        """Block until the worker is idle (tests / demo scripts)."""
        end = time.time() + timeout
        while time.time() < end:
            with self._cv:
                if not self._pending and not self._running:
                    return True
            time.sleep(0.02)
        return False

    def stop(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()

    # ---- worker --------------------------------------------------------------
    def _loop(self) -> None:
        while True:
            with self._cv:
                while not self._pending and not self._stop:
                    self._cv.wait(timeout=1.0)
                if self._stop:
                    return
                tenants = list(self._pending)
                self._pending.clear()
                self._running = True
            try:
                for t in tenants:
                    self.run_tenant(t)
            finally:
                with self._cv:
                    self._running = False
            time.sleep(self.cfg.aiops_min_interval_seconds)  # coalesce bursts

    # ---- the actual analysis ---------------------------------------------------
    def run_tenant(self, tenant_id: str) -> None:
        now = self.clock()
        try:
            stored = self.db.events_for_aiops(tenant_id, self.cfg.aiops_max_events)
            events = [normalize_event(e) for e in stored]
            ai_cfg = AIOpsConfig(collector_offline_timeout_seconds=self.cfg.hb_poor_after_seconds)
            result = AegisAIOpsPipeline(ai_cfg).run(events, reference_time_utc=_iso(now), tenant=tenant_id)
            self._reconcile_incidents(tenant_id, result["incidents"], now, ai_cfg.correlation_window_seconds)
            self.db.save_snapshot(tenant_id, {
                "anomalies": result["anomalies"],
                "dependency_graph": result["dependency_graph"],
                "aiops_health": result["health"],
                "events_analyzed": len(events),
            }, now)
            self.runs += 1
        except Exception as exc:  # never let AIOps affect ingestion
            self.db.add_aiops_error(tenant_id, now, f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}")

    def _reconcile_incidents(self, tenant_id: str, new: list[dict[str, Any]], now: float, window: int) -> None:
        """Give each re-computed incident the id of the stored incident it continues."""
        stored = [b for b in self.db.all_incident_bodies(tenant_id) if b.get("source") == "aiops-deterministic"]
        max_seq = 0
        for b in self.db.all_incident_bodies(tenant_id):
            m = re.fullmatch(r"INC-(\d+)", str(b.get("incident_id", "")))
            if m:
                max_seq = max(max_seq, int(m.group(1)))
        used: set[str] = set()
        for inc in sorted(new, key=lambda i: i["first_observed_utc"]):
            svcs = {s["service_id"] for s in inc.get("affected_services", [])}
            first = parse_utc_timestamp(inc["first_observed_utc"]).timestamp()
            match = None
            for b in stored:
                if b["incident_id"] in used:
                    continue
                b_svcs = {s["service_id"] for s in b.get("affected_services", [])}
                b_first = parse_utc_timestamp(b["first_observed_utc"]).timestamp()
                if svcs & b_svcs and abs(first - b_first) <= window:
                    match = b
                    break
            if match:
                inc["incident_id"] = match["incident_id"]
            else:
                max_seq += 1
                inc["incident_id"] = f"INC-{max_seq:04d}"
            used.add(inc["incident_id"])
            inc["tenant_id"] = tenant_id
            inc["source"] = "aiops-deterministic"
            inc["last_updated_utc"] = _iso(now)
            self.db.upsert_incident(tenant_id, inc["incident_id"], inc, now)
