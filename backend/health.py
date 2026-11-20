"""Four health states, computed separately for collectors and infrastructure."""

from __future__ import annotations

import json
from typing import Any

from .config import Settings

ORDER = ["excellent", "good", "fair", "poor"]
SEVERITY_TO_STATE = {"info": "excellent", "warning": "good", "high": "fair", "critical": "poor"}


def worst(*states: str) -> str:
    return max(states, key=ORDER.index)


def collector_health(row: dict, now: float, cfg: Settings) -> dict[str, Any]:
    """Heartbeat age drives it; backlog and stale telemetry can only downgrade."""
    reasons: list[str] = []
    state = "excellent"

    hb = row.get("last_heartbeat_at")
    if hb is None:
        return {"state": "poor", "reasons": ["no heartbeat received yet"], "heartbeat_age_seconds": None}
    age = now - hb
    if age >= cfg.hb_poor_after_seconds:
        state = worst(state, "poor"); reasons.append(f"no heartbeat for {int(age)}s (>= {cfg.hb_poor_after_seconds}s)")
    elif age >= cfg.hb_fair_after_seconds:
        state = worst(state, "fair"); reasons.append(f"heartbeat late: {int(age)}s")
    elif age >= cfg.hb_good_after_seconds:
        state = worst(state, "good"); reasons.append(f"heartbeat slightly late: {int(age)}s")

    backlog = row.get("queue_backlog") or 0
    if backlog > cfg.backlog_poor_above:
        state = worst(state, "poor"); reasons.append(f"queue backlog {backlog}")
    elif backlog > cfg.backlog_fair_above:
        state = worst(state, "fair"); reasons.append(f"queue backlog {backlog}")
    elif backlog > cfg.backlog_good_above:
        state = worst(state, "good"); reasons.append(f"queue backlog {backlog}")

    tel = row.get("last_telemetry_at")
    if tel is not None:
        tage = now - tel
        if tage >= cfg.telemetry_fair_after_seconds:
            state = worst(state, "fair"); reasons.append(f"telemetry stale {int(tage)}s")
        elif tage >= cfg.telemetry_good_after_seconds:
            state = worst(state, "good"); reasons.append(f"telemetry stale {int(tage)}s")

    if not reasons:
        reasons.append("heartbeats on time, queue small")
    return {"state": state, "reasons": reasons, "heartbeat_age_seconds": round(age, 1)}


def infrastructure_health(metric_rows: list[dict]) -> list[dict[str, Any]]:
    """Per service: worst severity among the LATEST metric of each name in the window.

    Metrics tagged health_scope=collector are excluded (that is collector health).
    """
    latest: dict[tuple[str, str], dict] = {}
    for r in metric_rows:  # already newest first
        body = json.loads(r["body"])
        if body.get("health_scope") == "collector":
            continue
        key = (r["service_id"], body["metric_name"])
        if key not in latest:
            latest[key] = {"severity": r["severity"], "metric_name": body["metric_name"],
                           "value": body["metric_value"], "unit": body["unit"],
                           "timestamp_utc": r["timestamp_utc"], "service_id": r["service_id"]}
    services: dict[str, dict[str, Any]] = {}
    for (svc, _), m in latest.items():
        s = services.setdefault(svc, {"service_id": svc, "state": "excellent", "reasons": [], "latest": []})
        s["latest"].append({k: m[k] for k in ("metric_name", "value", "unit", "severity", "timestamp_utc")})
        st = SEVERITY_TO_STATE[m["severity"]]
        if st != "excellent":
            s["reasons"].append(f"{m['metric_name']}={m['value']}{m['unit']} severity {m['severity']}")
        s["state"] = worst(s["state"], st)
    for s in services.values():
        if not s["reasons"]:
            s["reasons"].append("all recent metrics normal")
        s["latest"].sort(key=lambda x: x["metric_name"])
    return sorted(services.values(), key=lambda s: s["service_id"])
