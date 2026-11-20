"""Shared event contract validation and canonical SHA-256 egress hashing.

Adheres strictly to shared/event_schema.json without modifying it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

COMMON_REQUIRED_FIELDS = (
    "event_id",
    "collector_id",
    "event_type",
    "timestamp_utc",
    "source_timezone",
    "region",
    "severity",
    "policy_version",
)
# service_id is required for metric and auth_failure_summary events. Heartbeats describe
# the collector itself and may omit it (shared schema: optional on heartbeat).
SERVICE_ID_REQUIRED_TYPES = ("metric", "auth_failure_summary")

EVENT_TYPE_REQUIRED_FIELDS = {
    # Optional per the shared schema (not required here): metric window_seconds, health_scope,
    # resource_id, dependency_id; heartbeat collector_version, cpu_percent, memory_percent,
    # queue_backlog.
    "metric": (
        "metric_name",
        "metric_value",
        "unit",
    ),
    "heartbeat": (
        "health_scope",
        "health_state",
    ),
    "auth_failure_summary": (
        "failure_count",
        "window_seconds",
        "summary_code",
    ),
}

VALID_SEVERITIES = {"info", "low", "medium", "warning", "high", "critical"}


def load_shared_schema(repo_root: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Load shared/event_schema.json if present in the repository root."""
    root = repo_root or Path(__file__).resolve().parent.parent
    schema_path = root / "shared" / "event_schema.json"
    if schema_path.exists():
        with schema_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    return None


def canonical_payload_json(event: Dict[str, Any]) -> str:
    """Serialize an approved event payload canonically for deterministic SHA-256 hashing."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_sha256(event: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of an approved event payload."""
    return hashlib.sha256(canonical_payload_json(event).encode("utf-8")).hexdigest()


def verify_event_hash(event: Dict[str, Any], expected_sha256: str) -> bool:
    """Verify an approved event payload against its expected SHA-256 digest."""
    return compute_event_sha256(event) == expected_sha256


def validate_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate an event against the Aegis core event contract.

    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []
    if not isinstance(event, dict):
        return False, ["Event must be a JSON object."]

    for field in COMMON_REQUIRED_FIELDS:
        if field not in event or event[field] is None or event[field] == "":
            errors.append(f"Missing required common field: {field}")

    event_type = event.get("event_type")
    if event_type not in EVENT_TYPE_REQUIRED_FIELDS:
        errors.append(
            f"Unsupported event_type '{event_type}'. Expected one of {sorted(EVENT_TYPE_REQUIRED_FIELDS)}."
        )
    else:
        for field in EVENT_TYPE_REQUIRED_FIELDS[event_type]:
            if field not in event:
                errors.append(f"Missing required '{event_type}' field: {field}")

    if event_type in SERVICE_ID_REQUIRED_TYPES and not event.get("service_id"):
        errors.append(f"Missing required '{event_type}' field: service_id")

    if event_type == "metric":
        val = event.get("metric_value")
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            errors.append("metric_value must be a numeric value.")
        win = event.get("window_seconds")
        if win is not None and (not isinstance(win, (int, float)) or isinstance(win, bool) or win <= 0):
            errors.append("window_seconds must be a positive number when present.")

    elif event_type == "heartbeat":
        for num_field in ("cpu_percent", "memory_percent", "queue_backlog"):
            val = event.get(num_field)
            if val is not None and (not isinstance(val, (int, float)) or isinstance(val, bool)):
                errors.append(f"{num_field} must be numeric when present.")

    elif event_type == "auth_failure_summary":
        fc = event.get("failure_count")
        if not isinstance(fc, int) or isinstance(fc, bool) or fc < 0:
            errors.append("failure_count must be a non-negative integer.")

    return len(errors) == 0, errors
