"""Deterministic demo data source. Stands in for real adapters.

Scenarios (all deterministic given a seed):
  normal              steady, healthy metrics
  payment_latency_spike  payment-service latency jumps and stays high (database stays normal)
  cpu_spike           payment-service CPU climbs high
  network_degradation latency + packet loss rise on api-gateway
  auth_attack         burst of failed logins on auth-service
  secret_injection    raw log lines containing fake secrets (must stay local)
"""

from __future__ import annotations

import random
from typing import Any, Iterator

SERVICES = ["api-gateway", "payment-service", "database"]
SCENARIOS = [
    "normal",
    "payment_latency_spike",
    "cpu_spike",
    "network_degradation",
    "auth_attack",
    "secret_injection",
]

# Fake values only. Used by the demo and tests to prove they never leave.
FAKE_API_KEY = "sk-live-4eC39HqLyjWDarjtT1zdp7dc"
FAKE_EMAIL = "alice.demo@example.com"
FAKE_CARD = "4111 1111 1111 1111"


def _metric(service: str, name: str, value: float, unit: str, severity: str = "info",
            raw_line: str | None = None) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "kind": "metric",
        "service_id": service,
        "metric_name": name,
        "value": round(value, 2),
        "unit": unit,
        "severity": severity,
    }
    if raw_line:
        rec["raw_line"] = raw_line
    return rec


def records_for_tick(scenario: str, tick: int, rng: random.Random) -> list[dict[str, Any]]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    out: list[dict[str, Any]] = []
    for svc in SERVICES:
        cpu = 30 + rng.uniform(-5, 5)
        lat = 40 + rng.uniform(-8, 8)
        mem = 45 + rng.uniform(-4, 4)
        pkt = 0.08 + rng.uniform(-0.04, 0.04)
        cpu_sev = lat_sev = mem_sev = pkt_sev = "info"
        if scenario == "cpu_spike" and svc == "payment-service" and tick >= 3:
            cpu = min(99.0, 70 + tick * 3 + rng.uniform(0, 3))
            cpu_sev = "high"
        if scenario == "payment_latency_spike" and tick >= 8:
            # first 8 ticks are the healthy baseline the AIOps engine learns from
            if svc == "payment-service":
                lat, lat_sev = 620 + rng.uniform(0, 40), "critical"
            elif svc == "api-gateway":
                lat, lat_sev = 280 + rng.uniform(0, 30), "warning"
        if scenario == "network_degradation" and svc == "api-gateway" and tick >= 3:
            lat, lat_sev = 250 + tick * 20 + rng.uniform(0, 20), "high"
            pkt, pkt_sev = 4 + rng.uniform(0, 3), "high"
        out.append(_metric(svc, "cpu_percent", cpu, "percent", cpu_sev))
        out.append(_metric(svc, "latency_ms", lat, "ms", lat_sev))
        out.append(_metric(svc, "memory_percent", mem, "percent", mem_sev))
        out.append(_metric(svc, "packet_loss_percent", max(0.0, pkt), "percent", pkt_sev))

    if scenario == "network_degradation" and tick >= 3:
        out.append(_metric("api-gateway", "packet_loss_percent", 4 + rng.uniform(0, 3), "percent", "high"))

    if scenario == "auth_attack" and tick >= 2:
        for i in range(6):
            out.append(
                {
                    "kind": "auth",
                    "service_id": "auth-service",
                    "outcome": "failure",
                    "raw_line": f"login failed user=alice{i} ip=203.0.113.{10 + i} from client",
                }
            )

    if scenario == "secret_injection":
        out.append(
            _metric(
                "payment-service",
                "cpu_percent",
                35 + rng.uniform(-3, 3),
                "percent",
                "info",
                raw_line=(
                    f"charge ok api_key={FAKE_API_KEY} customer={FAKE_EMAIL} card={FAKE_CARD}"
                ),
            )
        )
    return out


def stream(scenario: str, seed: int = 7) -> Iterator[list[dict[str, Any]]]:
    rng = random.Random(seed)
    tick = 0
    while True:
        yield records_for_tick(scenario, tick, rng)
        tick += 1
