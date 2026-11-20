"""Collector configuration, read from AEGIS_* environment variables.

The token is never printed: it is excluded from repr and never logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import __version__


@dataclass(frozen=True)
class Config:
    endpoint: str = "http://localhost:8000/api/v1/events"
    token: str = field(default="", repr=False)
    collector_id: str = "collector-001"
    region: str = "ap-south"
    source_timezone: str = "Asia/Kolkata"
    policy_version: str = "v1"
    db_path: str = "collector.db"
    collector_version: str = __version__

    tick_seconds: float = 2.0
    heartbeat_seconds: float = 5.0
    raw_retention_seconds: int = 3600

    # Delivery
    request_timeout: float = 5.0
    backoff_base: float = 1.0
    backoff_max: float = 60.0
    backoff_jitter: float = 0.1
    batch_size: int = 50

    # Failed-login aggregation
    auth_window_seconds: int = 60
    auth_threshold: int = 10

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ
        d = cls()
        return cls(
            endpoint=env.get("AEGIS_ENDPOINT", d.endpoint),
            token=env.get("AEGIS_COLLECTOR_TOKEN", d.token),
            collector_id=env.get("AEGIS_COLLECTOR_ID", d.collector_id),
            region=env.get("AEGIS_REGION", d.region),
            source_timezone=env.get("AEGIS_SOURCE_TZ", d.source_timezone),
            policy_version=env.get("AEGIS_POLICY_VERSION", d.policy_version),
            db_path=env.get("AEGIS_DB_PATH", d.db_path),
            collector_version=env.get("AEGIS_COLLECTOR_VERSION", d.collector_version),
            tick_seconds=float(env.get("AEGIS_TICK_SECONDS", d.tick_seconds)),
            heartbeat_seconds=float(env.get("AEGIS_HEARTBEAT_SECONDS", d.heartbeat_seconds)),
            raw_retention_seconds=int(env.get("AEGIS_RAW_RETENTION_SECONDS", d.raw_retention_seconds)),
            request_timeout=float(env.get("AEGIS_REQUEST_TIMEOUT", d.request_timeout)),
            backoff_base=float(env.get("AEGIS_BACKOFF_BASE", d.backoff_base)),
            backoff_max=float(env.get("AEGIS_BACKOFF_MAX", d.backoff_max)),
            backoff_jitter=float(env.get("AEGIS_BACKOFF_JITTER", d.backoff_jitter)),
            batch_size=int(env.get("AEGIS_BATCH_SIZE", d.batch_size)),
            auth_window_seconds=int(env.get("AEGIS_AUTH_WINDOW_SECONDS", d.auth_window_seconds)),
            auth_threshold=int(env.get("AEGIS_AUTH_THRESHOLD", d.auth_threshold)),
        )
