"""Backend event -> AIOps event adapter (name normalisation only; never invents values).

The wire contract (shared/event_schema.json) is authoritative. This module maps legacy
or alternative names onto the names the AIOps detector is configured for, and keeps the
original measurement meaning (same unit, same value). Original names are preserved in
`original_metric_name` / `original_service_id` when something was changed.
"""

from __future__ import annotations

from typing import Any, Dict

# alias -> canonical metric name (units are identical: percent / ms)
METRIC_ALIASES = {
    "cpu_usage": "cpu_percent",
    "cpu_utilization": "cpu_percent",
    "memory_usage": "memory_percent",
    "memory_utilization": "memory_percent",
    "packet_loss_pct": "packet_loss_percent",
    "packet_loss": "packet_loss_percent",
    "latency": "latency_ms",
}

# alias -> service id in the hand-defined dependency graph
SERVICE_ALIASES = {
    "payment-api": "payment-service",
    "payments-db": "database",
    "payment-db": "database",
    "db": "database",
}

# Aegis four health states -> vocabulary the detector understands
HEALTH_STATE_MAP = {
    "excellent": "healthy",
    "good": "healthy",
    "fair": "degraded",
    "poor": "unhealthy",
}


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalised copy. The input (the stored, validated event) is not modified."""
    ev = dict(event)
    metric = ev.get("metric_name")
    if isinstance(metric, str) and metric in METRIC_ALIASES:
        ev["original_metric_name"] = metric
        ev["metric_name"] = METRIC_ALIASES[metric]
    svc = ev.get("service_id")
    if isinstance(svc, str) and svc in SERVICE_ALIASES:
        ev["original_service_id"] = svc
        ev["service_id"] = SERVICE_ALIASES[svc]
    if ev.get("event_type") == "heartbeat":
        state = str(ev.get("health_state", "")).lower()
        ev["original_health_state"] = ev.get("health_state")
        ev["health_state"] = HEALTH_STATE_MAP.get(state, state)
    return ev
