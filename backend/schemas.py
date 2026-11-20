"""Strict event schemas (shared/event_schema.json is generated from these)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
REGION = r"^[a-z0-9][a-z0-9-]{1,31}$"
TZ = r"^[A-Za-z_]+(?:/[A-Za-z0-9_+-]+)*$"
VER = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$"

Severity = Literal["info", "warning", "high", "critical"]
HealthScope = Literal["collector", "infrastructure"]
HealthState = Literal["excellent", "good", "fair", "poor"]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str = Field(pattern=ID)
    collector_id: str = Field(pattern=ID)
    timestamp_utc: str
    source_timezone: str = Field(pattern=TZ)
    region: str = Field(pattern=REGION)
    severity: Severity
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

    @field_validator("timestamp_utc")
    @classmethod
    def _utc_iso(cls, v: str) -> str:
        try:
            dt = datetime.fromisoformat(v)
        except ValueError as exc:
            raise ValueError("timestamp_not_iso8601") from exc
        if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(None):
            raise ValueError("timestamp_not_utc")
        return v

    @property
    def ts_epoch(self) -> float:
        return datetime.fromisoformat(self.timestamp_utc).timestamp()


class MetricEvent(_Base):
    event_type: Literal["metric"]
    service_id: str = Field(pattern=ID)
    metric_name: str = Field(pattern=ID)
    metric_value: float = Field(allow_inf_nan=False)
    unit: str = Field(pattern=ID)
    window_seconds: int | None = Field(default=None, ge=1, le=86400)
    health_scope: HealthScope | None = None
    resource_id: str | None = Field(default=None, pattern=ID)
    dependency_id: str | None = Field(default=None, pattern=ID)


class HeartbeatEvent(_Base):
    event_type: Literal["heartbeat"]
    service_id: str | None = Field(default=None, pattern=ID)
    health_scope: HealthScope
    health_state: HealthState
    collector_version: str = Field(pattern=VER)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    queue_backlog: int | None = Field(default=None, ge=0)


class AuthFailureSummaryEvent(_Base):
    event_type: Literal["auth_failure_summary"]
    service_id: str = Field(pattern=ID)
    failure_count: int = Field(ge=0)
    window_seconds: int = Field(ge=1, le=86400)
    summary_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


Event = Annotated[
    Union[MetricEvent, HeartbeatEvent, AuthFailureSummaryEvent],
    Field(discriminator="event_type"),
]
EVENT_ADAPTER: TypeAdapter = TypeAdapter(Event)


class IncidentIn(BaseModel):
    """Proposed shape for AIOps -> backend. Coordinate with Person 3."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(pattern=ID)
    tenant_id: str = Field(pattern=ID)
    title: str = Field(max_length=200)
    severity: Severity
    status: Literal["open", "acknowledged", "resolved"] = "open"
    detected_at: str | None = None
    summary: str | None = Field(default=None, max_length=1000)
    alerts_collapsed: int = Field(default=0, ge=0)
    root_causes: list[dict] = Field(default_factory=list, max_length=10)
    evidence: list[dict] = Field(default_factory=list, max_length=50)


def safe_errors(exc) -> list[dict]:
    """Field path + error type only. Never echo submitted values."""
    return [{"field": ".".join(str(p) for p in e["loc"]), "type": e["type"]} for e in exc.errors()]
