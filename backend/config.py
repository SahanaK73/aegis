"""Backend configuration. All thresholds are prototype values and configurable.

Dev tokens are placeholders for two simulated tenants. Override with env vars:
  AEGIS_TOKEN_TENANT_A, AEGIS_TOKEN_TENANT_B, AEGIS_AIOPS_KEY, AEGIS_DB_PATH
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    name: str
    region: str  # the only region this tenant's collectors may report from


def _default_tenants() -> dict[str, Tenant]:
    return {
        os.environ.get("AEGIS_TOKEN_TENANT_A", "dev-token-tenant-a"): Tenant("tenant-a", "Tenant A (simulated bank)", "ap-south"),
        os.environ.get("AEGIS_TOKEN_TENANT_B", "dev-token-tenant-b"): Tenant("tenant-b", "Tenant B (simulated wallet)", "eu-west"),
    }


@dataclass(frozen=True)
class Settings:
    db_path: str = field(default_factory=lambda: os.environ.get("AEGIS_DB_PATH", "backend.db"))
    tokens: dict[str, Tenant] = field(default_factory=_default_tenants)  # bearer token -> tenant
    aiops_key: str = field(default_factory=lambda: os.environ.get("AEGIS_AIOPS_KEY", "dev-aiops-key"))

    # browser origins allowed to call the API (Vite dev server by default)
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o.strip() for o in os.environ.get(
            "AEGIS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()))

    # AIOps integration: "background" (worker thread, default), "sync" (inline, used by tests), "off"
    aiops_mode: str = field(default_factory=lambda: os.environ.get("AEGIS_AIOPS_MODE", "background"))
    aiops_min_interval_seconds: float = 0.5   # coalesce bursts: at most one run per tenant per interval
    aiops_max_events: int = 3000              # lookback window (most recent stored events)

    max_body_bytes: int = 64 * 1024
    max_future_skew_seconds: int = 300
    late_after_seconds: int = 60  # event older than this on arrival => flagged "late"

    # collector health (heartbeat interval is 5 s)
    heartbeat_interval_seconds: int = 5
    hb_good_after_seconds: int = 10   # >= 2 missed beats
    hb_fair_after_seconds: int = 20   # >= 4 missed beats
    hb_poor_after_seconds: int = 45   # PDF rule: missing >= 45 s => Poor
    backlog_good_above: int = 10
    backlog_fair_above: int = 100
    backlog_poor_above: int = 500
    telemetry_good_after_seconds: int = 60   # stale telemetry downgrades
    telemetry_fair_after_seconds: int = 120

    # infrastructure health
    infra_window_seconds: int = 60

    def tenant_by_id(self, tenant_id: str) -> Tenant | None:
        for t in self.tokens.values():
            if t.tenant_id == tenant_id:
                return t
        return None
