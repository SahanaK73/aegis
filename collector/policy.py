"""Outbound policy: default-deny allow-list, strict per-event-type schemas, final check.

All outbound string fields are either an enumerated value or a strict identifier
pattern (no spaces), so arbitrary free text cannot pass. Error messages name fields
only and never echo values, so a rejected secret is not leaked into logs.

To rename fields or add event types, edit SCHEMAS and the rule tables below. Nothing
else in the collector hard-codes field names.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Any, Callable

from .redaction import find_sensitive


class PolicyViolation(Exception):
    """Raised when an event may not leave the customer environment."""


# ---- value rules -----------------------------------------------------------

_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_REGION = re.compile(r"[a-z0-9][a-z0-9-]{1,31}")
_TZ = re.compile(r"[A-Za-z_]+(?:/[A-Za-z0-9_+-]+)*")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,31}")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

SEVERITIES = {"info", "warning", "high", "critical"}
HEALTH_SCOPES = {"collector", "infrastructure"}
HEALTH_STATES = {"excellent", "good", "fair", "poor"}
EVENT_TYPES = {"metric", "heartbeat", "auth_failure_summary"}
METRIC_NAMES = {
    # canonical names (match the AIOps engine configuration)
    "cpu_percent",
    "memory_percent",
    "latency_ms",
    "packet_loss_percent",
    # additional / legacy names still accepted; the backend normalises aliases for AIOps
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "packet_loss_pct",
    "bandwidth_mbps",
}
UNITS = {"percent", "ms", "count", "mbps"}
SUMMARY_CODES = {"REPEATED_AUTH_FAILURE"}


def _ident(v: Any) -> bool:
    return isinstance(v, str) and _IDENT.fullmatch(v) is not None


def _fullmatch(pattern: "re.Pattern[str]") -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and pattern.fullmatch(v) is not None


def _enum(values: set[str]) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and v in values


def _num(lo: float | None = None, hi: float | None = None) -> Callable[[Any], bool]:
    def check(v: Any) -> bool:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return False
        if not math.isfinite(v):
            return False
        return (lo is None or v >= lo) and (hi is None or v <= hi)

    return check


def _int(lo: int, hi: int) -> Callable[[Any], bool]:
    def check(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi

    return check


def _timestamp(v: Any) -> bool:
    if not isinstance(v, str) or _TS.fullmatch(v) is None:
        return False
    try:
        datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


FIELD_RULES: dict[str, Callable[[Any], bool]] = {
    # envelope
    "event_id": _ident,
    "collector_id": _ident,
    "event_type": _enum(EVENT_TYPES),
    "service_id": _ident,
    "timestamp_utc": _timestamp,
    "source_timezone": _fullmatch(_TZ),
    "region": _fullmatch(_REGION),
    "severity": _enum(SEVERITIES),
    "policy_version": _fullmatch(re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")),
    # metric
    "metric_name": _enum(METRIC_NAMES),
    "metric_value": _num(-1e12, 1e12),
    "unit": _enum(UNITS),
    "window_seconds": _int(1, 86400),
    "health_scope": _enum(HEALTH_SCOPES),
    "resource_id": _ident,
    "dependency_id": _ident,
    # heartbeat
    "health_state": _enum(HEALTH_STATES),
    "collector_version": _fullmatch(_VERSION),
    "cpu_percent": _num(0, 100),
    "memory_percent": _num(0, 100),
    "queue_backlog": _int(0, 10**9),
    # auth_failure_summary
    "failure_count": _int(0, 10**9),
    "summary_code": _enum(SUMMARY_CODES),
}

ENVELOPE_REQUIRED = {
    "event_id",
    "collector_id",
    "event_type",
    "timestamp_utc",
    "source_timezone",
    "region",
    "severity",
    "policy_version",
}

# Per-event-type fields beyond the envelope.
SCHEMAS: dict[str, dict[str, set[str]]] = {
    "metric": {
        "required": {"service_id", "metric_name", "metric_value", "unit"},
        "optional": {"window_seconds", "health_scope", "resource_id", "dependency_id"},
    },
    "heartbeat": {
        "required": {"health_scope", "health_state", "collector_version"},
        "optional": {"service_id", "cpu_percent", "memory_percent", "queue_backlog"},
    },
    "auth_failure_summary": {
        "required": {"service_id", "failure_count", "window_seconds", "summary_code"},
        "optional": set(),
    },
}


def _safe_name(name: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "?", str(name))[:40]


def allowed_fields(event_type: str) -> set[str]:
    schema = SCHEMAS[event_type]
    return ENVELOPE_REQUIRED | schema["required"] | schema["optional"]


def enforce_allowlist(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Default-deny: keep only allow-listed fields. Returns (clean, dropped_field_names)."""
    event_type = candidate.get("event_type")
    if event_type not in SCHEMAS:
        raise PolicyViolation("unknown event_type")
    allowed = allowed_fields(event_type)
    clean = {k: v for k, v in candidate.items() if k in allowed}
    dropped = sorted(_safe_name(k) for k in candidate if k not in allowed)
    return clean, dropped


def validate_outbound(event: Any) -> None:
    """Strict final validation. Raises PolicyViolation if the event may not leave."""
    if not isinstance(event, dict):
        raise PolicyViolation("event must be an object")
    event_type = event.get("event_type")
    if event_type not in SCHEMAS:
        raise PolicyViolation("unknown event_type")

    allowed = allowed_fields(event_type)
    unknown = sorted(_safe_name(k) for k in event if k not in allowed)
    if unknown:
        raise PolicyViolation("unknown field(s): " + ",".join(unknown))

    required = ENVELOPE_REQUIRED | SCHEMAS[event_type]["required"]
    missing = sorted(required - set(event))
    if missing:
        raise PolicyViolation("missing field(s): " + ",".join(missing))

    for name, value in event.items():
        rule = FIELD_RULES.get(name)
        if rule is None or not rule(value):
            raise PolicyViolation(f"invalid value for field: {_safe_name(name)}")

    if event_type == "heartbeat" and event["health_scope"] != "collector":
        raise PolicyViolation("heartbeat health_scope must be 'collector'")

    # Defense in depth: scan the serialized event for anything that looks sensitive.
    hits = find_sensitive(json.dumps(event, sort_keys=True))
    if hits:
        raise PolicyViolation("sensitive pattern detected: " + ",".join(sorted(hits)))
