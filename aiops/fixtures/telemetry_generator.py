"""Realistic simulated telemetry fixtures adhering strictly to shared/event_schema.json.

Covers all 8 required scenarios:
1. normal_infrastructure
2. high_cpu
3. high_memory
4. latency_spike
5. packet_loss
6. repeated_failed_logins
7. collector_offline
8. correlated_anomalies
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


BASE_TIME = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
POLICY_VERSION = "aegis-privacy-v1.2"


def _ts(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def _metric_event(
    idx: int,
    collector_id: str,
    service_id: str,
    metric_name: str,
    metric_value: float,
    unit: str,
    offset_seconds: int,
    resource_id: str,
    dependency_id: str,
    region: str = "ap-south-1",
    severity: str = "info",
    prefix: str = "evt",
) -> Dict[str, Any]:
    return {
        "event_id": f"{prefix}-m-{idx:04d}",
        "collector_id": collector_id,
        "event_type": "metric",
        "service_id": service_id,
        "timestamp_utc": _ts(offset_seconds),
        "source_timezone": "Asia/Kolkata",
        "region": region,
        "severity": severity,
        "policy_version": POLICY_VERSION,
        "metric_name": metric_name,
        "metric_value": metric_value,
        "unit": unit,
        "window_seconds": 30,
        "health_scope": "service",
        "resource_id": resource_id,
        "dependency_id": dependency_id,
    }


def _heartbeat_event(
    idx: int,
    collector_id: str,
    service_id: str,
    offset_seconds: int,
    health_state: str = "healthy",
    cpu_percent: float = 28.0,
    memory_percent: float = 42.0,
    queue_backlog: int = 4,
    region: str = "ap-south-1",
    prefix: str = "evt",
) -> Dict[str, Any]:
    severity = "info" if health_state == "healthy" else "critical"
    return {
        "event_id": f"{prefix}-hb-{idx:04d}",
        "collector_id": collector_id,
        "event_type": "heartbeat",
        "service_id": service_id,
        "timestamp_utc": _ts(offset_seconds),
        "source_timezone": "Asia/Kolkata",
        "region": region,
        "severity": severity,
        "policy_version": POLICY_VERSION,
        "health_scope": "collector",
        "health_state": health_state,
        "collector_version": "0.4.2",
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "queue_backlog": queue_backlog,
    }


def _auth_failure_event(
    idx: int,
    collector_id: str,
    service_id: str,
    offset_seconds: int,
    failure_count: int,
    summary_code: str = "AUTH_BURST_401",
    region: str = "ap-south-1",
    prefix: str = "evt",
) -> Dict[str, Any]:
    severity = "critical" if failure_count >= 50 else ("warning" if failure_count >= 15 else "info")
    return {
        "event_id": f"{prefix}-af-{idx:04d}",
        "collector_id": collector_id,
        "event_type": "auth_failure_summary",
        "service_id": service_id,
        "timestamp_utc": _ts(offset_seconds),
        "source_timezone": "Asia/Kolkata",
        "region": region,
        "severity": severity,
        "policy_version": POLICY_VERSION,
        "failure_count": failure_count,
        "window_seconds": 60,
        "summary_code": summary_code,
    }


def _baseline_warmup_events(prefix: str, steps: int = 6) -> List[Dict[str, Any]]:
    """Generate clean baseline warm-up telemetry across all 4 payment architecture services."""
    events: List[Dict[str, Any]] = []
    idx = 1
    cpu_vals = [31.2, 33.5, 32.1, 34.0, 32.8, 33.1]
    mem_vals = [46.0, 46.8, 47.2, 46.5, 47.0, 46.9]
    lat_gw = [48.0, 51.0, 49.5, 52.0, 50.2, 49.8]
    lat_pay = [72.0, 75.0, 73.5, 76.0, 74.2, 75.1]
    pkt_net = [0.1, 0.12, 0.08, 0.11, 0.09, 0.1]

    for i in range(steps):
        t = i * 30
        events.append(_metric_event(idx, "col-db-01", "database", "cpu_percent", cpu_vals[i % 6], "percent", t, "db-primary-01", "none", prefix=prefix))
        idx += 1
        events.append(_metric_event(idx, "col-db-01", "database", "memory_percent", mem_vals[i % 6], "percent", t, "db-primary-01", "none", prefix=prefix))
        idx += 1
        events.append(_metric_event(idx, "col-pay-01", "payment-service", "latency_ms", lat_pay[i % 6], "ms", t, "pay-pod-01", "database", prefix=prefix))
        idx += 1
        events.append(_metric_event(idx, "col-gw-01", "api-gateway", "latency_ms", lat_gw[i % 6], "ms", t, "gw-edge-01", "payment-service", prefix=prefix))
        idx += 1
        events.append(_metric_event(idx, "col-net-01", "network-service", "packet_loss_percent", pkt_net[i % 6], "percent", t, "mesh-link-01", "payment-service", prefix=prefix))
        idx += 1

    # Healthy heartbeats for all 4 collectors at t=150
    t_hb = (steps - 1) * 30
    events.extend(
        [
            _heartbeat_event(1, "col-gw-01", "api-gateway", t_hb, cpu_percent=24.0, memory_percent=38.0, queue_backlog=2, prefix=prefix),
            _heartbeat_event(2, "col-pay-01", "payment-service", t_hb, cpu_percent=35.0, memory_percent=49.0, queue_backlog=5, prefix=prefix),
            _heartbeat_event(3, "col-db-01", "database", t_hb, cpu_percent=33.0, memory_percent=47.0, queue_backlog=3, prefix=prefix),
            _heartbeat_event(4, "col-net-01", "network-service", t_hb, cpu_percent=18.0, memory_percent=31.0, queue_backlog=1, prefix=prefix),
        ]
    )
    return events


def scenario_normal_infrastructure() -> Dict[str, Any]:
    events = _baseline_warmup_events("norm", steps=8)
    return {
        "label": "Normal Infrastructure",
        "description": "All four payment architecture services and collectors operating within rolling baselines.",
        "events": events,
    }


def scenario_high_cpu() -> Dict[str, Any]:
    events = _baseline_warmup_events("cpu", steps=6)
    idx = 100
    for step, val in enumerate([84.5, 91.2, 95.8, 96.4]):
        t = 180 + step * 30
        events.append(
            _metric_event(idx, "col-db-01", "database", "cpu_percent", val, "percent", t, "db-primary-01", "none", severity="critical", prefix="cpu")
        )
        idx += 1
        # Keep memory normal to demonstrate contradicting/scoping evidence
        events.append(
            _metric_event(idx, "col-db-01", "database", "memory_percent", 48.2, "percent", t, "db-primary-01", "none", severity="info", prefix="cpu")
        )
        idx += 1
    events.append(_heartbeat_event(20, "col-db-01", "database", 270, cpu_percent=96.0, memory_percent=48.2, queue_backlog=12, prefix="cpu"))
    events.append(_heartbeat_event(21, "col-pay-01", "payment-service", 270, prefix="cpu"))
    events.append(_heartbeat_event(22, "col-gw-01", "api-gateway", 270, prefix="cpu"))
    events.append(_heartbeat_event(23, "col-net-01", "network-service", 270, prefix="cpu"))
    return {
        "label": "High CPU (Database)",
        "description": "Sustained Database CPU saturation (4 consecutive baseline deviations) while memory remains normal.",
        "events": events,
    }


def scenario_high_memory() -> Dict[str, Any]:
    events = _baseline_warmup_events("mem", steps=6)
    idx = 200
    for step, val in enumerate([85.1, 89.4, 93.7, 95.2]):
        t = 180 + step * 30
        events.append(
            _metric_event(idx, "col-db-01", "database", "memory_percent", val, "percent", t, "db-primary-01", "none", severity="critical", prefix="mem")
        )
        idx += 1
    events.append(_heartbeat_event(30, "col-db-01", "database", 270, cpu_percent=38.0, memory_percent=95.2, queue_backlog=18, prefix="mem"))
    events.append(_heartbeat_event(31, "col-pay-01", "payment-service", 270, prefix="mem"))
    events.append(_heartbeat_event(32, "col-gw-01", "api-gateway", 270, prefix="mem"))
    events.append(_heartbeat_event(33, "col-net-01", "network-service", 270, prefix="mem"))
    return {
        "label": "High Memory (Database)",
        "description": "Sustained Database memory pressure exceeding rolling statistical baseline.",
        "events": events,
    }


def scenario_latency_spike() -> Dict[str, Any]:
    events = _baseline_warmup_events("lat", steps=6)
    idx = 300
    for step, val in enumerate([310.0, 445.0, 560.0, 610.0]):
        t = 180 + step * 30
        events.append(
            _metric_event(idx, "col-pay-01", "payment-service", "latency_ms", val, "ms", t, "pay-pod-01", "database", severity="critical", prefix="lat")
        )
        idx += 1
    events.append(_heartbeat_event(40, "col-db-01", "database", 270, prefix="lat"))
    events.append(_heartbeat_event(41, "col-pay-01", "payment-service", 270, prefix="lat"))
    events.append(_heartbeat_event(42, "col-gw-01", "api-gateway", 270, prefix="lat"))
    events.append(_heartbeat_event(43, "col-net-01", "network-service", 270, prefix="lat"))
    return {
        "label": "Latency Spike (Payment Service)",
        "description": "Sustained p95 latency surge on Payment Service with healthy Database and Network baselines.",
        "events": events,
    }


def scenario_packet_loss() -> Dict[str, Any]:
    events = _baseline_warmup_events("pkt", steps=6)
    idx = 400
    for step, val in enumerate([3.2, 4.8, 6.4, 7.1]):
        t = 180 + step * 30
        events.append(
            _metric_event(idx, "col-net-01", "network-service", "packet_loss_percent", val, "percent", t, "mesh-link-01", "payment-service", severity="critical", prefix="pkt")
        )
        idx += 1
    events.append(_heartbeat_event(50, "col-db-01", "database", 270, prefix="pkt"))
    events.append(_heartbeat_event(51, "col-pay-01", "payment-service", 270, prefix="pkt"))
    events.append(_heartbeat_event(52, "col-gw-01", "api-gateway", 270, prefix="pkt"))
    events.append(_heartbeat_event(53, "col-net-01", "network-service", 270, queue_backlog=44, prefix="pkt"))
    return {
        "label": "Packet Loss (Network Service)",
        "description": "Sustained packet loss on Network Service transport link feeding Payment Service.",
        "events": events,
    }


def scenario_repeated_failed_logins() -> Dict[str, Any]:
    events = _baseline_warmup_events("auth", steps=6)
    events.append(_auth_failure_event(1, "col-gw-01", "api-gateway", 180, failure_count=28, summary_code="AUTH_BURST_401", prefix="auth"))
    events.append(_auth_failure_event(2, "col-gw-01", "api-gateway", 240, failure_count=74, summary_code="AUTH_CRED_STUFF_401", prefix="auth"))
    events.append(_heartbeat_event(60, "col-db-01", "database", 240, prefix="auth"))
    events.append(_heartbeat_event(61, "col-pay-01", "payment-service", 240, prefix="auth"))
    events.append(_heartbeat_event(62, "col-gw-01", "api-gateway", 240, prefix="auth"))
    events.append(_heartbeat_event(63, "col-net-01", "network-service", 240, prefix="auth"))
    return {
        "label": "Repeated Failed Logins",
        "description": "Privacy-preserving aggregated auth failure summaries on API Gateway (zero PII/usernames).",
        "events": events,
    }


def scenario_collector_offline() -> Dict[str, Any]:
    events = _baseline_warmup_events("off", steps=6)
    # Other 3 collectors keep heartbeating at t=330, while col-net-01 stopped at t=150 (180s gap > 120s timeout)
    events.append(_heartbeat_event(70, "col-gw-01", "api-gateway", 330, prefix="off"))
    events.append(_heartbeat_event(71, "col-pay-01", "payment-service", 330, prefix="off"))
    events.append(_heartbeat_event(72, "col-db-01", "database", 330, prefix="off"))
    return {
        "label": "Collector Offline",
        "description": "Collector col-net-01 missed heartbeats beyond the 120s liveness threshold.",
        "events": events,
        "reference_time_utc": _ts(330),
    }


def scenario_correlated_anomalies() -> Dict[str, Any]:
    """Flagship multi-service cascading incident:
    Database CPU + memory surge starts at t=180s, followed by Payment Service latency at t=210s
    and API Gateway latency at t=240s, while Network Service packet loss remains healthy (contradicting evidence).
    """
    events = _baseline_warmup_events("corr", steps=6)
    idx = 800

    # Database CPU & memory surge first (t=180, 210, 240, 270)
    db_cpu = [86.0, 91.5, 96.2, 97.4]
    db_mem = [84.0, 88.5, 92.1, 94.6]
    for step in range(4):
        t = 180 + step * 30
        events.append(_metric_event(idx, "col-db-01", "database", "cpu_percent", db_cpu[step], "percent", t, "db-primary-01", "none", severity="critical", prefix="corr"))
        idx += 1
        events.append(_metric_event(idx, "col-db-01", "database", "memory_percent", db_mem[step], "percent", t, "db-primary-01", "none", severity="critical", prefix="corr"))
        idx += 1
        # Network service stays healthy during the incident window -> contradicting evidence against network root cause
        events.append(_metric_event(idx, "col-net-01", "network-service", "packet_loss_percent", 0.11, "percent", t, "mesh-link-01", "payment-service", severity="info", prefix="corr"))
        idx += 1

    # Payment Service latency cascades (t=210, 240, 270, 300)
    pay_lat = [295.0, 420.0, 585.0, 640.0]
    for step in range(4):
        t = 210 + step * 30
        events.append(_metric_event(idx, "col-pay-01", "payment-service", "latency_ms", pay_lat[step], "ms", t, "pay-pod-01", "database", severity="critical", prefix="corr"))
        idx += 1

    # API Gateway latency cascades (t=240, 270, 300)
    gw_lat = [310.0, 490.0, 675.0]
    for step in range(3):
        t = 240 + step * 30
        events.append(_metric_event(idx, "col-gw-01", "api-gateway", "latency_ms", gw_lat[step], "ms", t, "gw-edge-01", "payment-service", severity="critical", prefix="corr"))
        idx += 1

    # Heartbeats at t=300 (col-db-01 degraded with queue backlog)
    events.extend(
        [
            _heartbeat_event(80, "col-gw-01", "api-gateway", 300, cpu_percent=42.0, memory_percent=45.0, queue_backlog=8, prefix="corr"),
            _heartbeat_event(81, "col-pay-01", "payment-service", 300, cpu_percent=64.0, memory_percent=58.0, queue_backlog=34, prefix="corr"),
            _heartbeat_event(82, "col-db-01", "database", 300, health_state="degraded", cpu_percent=97.4, memory_percent=94.6, queue_backlog=240, prefix="corr"),
            _heartbeat_event(83, "col-net-01", "network-service", 300, cpu_percent=19.0, memory_percent=32.0, queue_backlog=2, prefix="corr"),
        ]
    )

    return {
        "label": "Correlated Payment Degradation",
        "description": "Database CPU/memory saturation cascading into Payment Service and API Gateway latency while Network Service remains healthy.",
        "events": events,
    }


def build_all_scenarios() -> Dict[str, Dict[str, Any]]:
    """Return all 8 required simulated telemetry scenarios keyed by scenario slug."""
    return {
        "correlated_anomalies": scenario_correlated_anomalies(),
        "normal_infrastructure": scenario_normal_infrastructure(),
        "high_cpu": scenario_high_cpu(),
        "high_memory": scenario_high_memory(),
        "latency_spike": scenario_latency_spike(),
        "packet_loss": scenario_packet_loss(),
        "repeated_failed_logins": scenario_repeated_failed_logins(),
        "collector_offline": scenario_collector_offline(),
    }
