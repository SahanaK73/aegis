"""End-to-end deterministic AIOps pipeline for Aegis.

Pipeline flow:
    Approved telemetry -> schema validation & SHA-256 egress audit
    -> deterministic anomaly detection -> incident correlation
    -> ranked evidence-backed root-cause hypotheses -> API-ready output
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .anomaly_detector import DeterministicAnomalyDetector, parse_utc_timestamp
from .config import AIOpsConfig, DEFAULT_CONFIG
from .correlator import IncidentCorrelator
from .dependency_graph import ServiceDependencyGraph
from .rca_engine import RootCauseAnalyzer
from .schema import compute_event_sha256, validate_event


class AegisAIOpsPipeline:
    """Runs the full deterministic AIOps pipeline over approved telemetry events."""

    def __init__(self, config: Optional[AIOpsConfig] = None) -> None:
        self.config = config or DEFAULT_CONFIG
        self.graph = ServiceDependencyGraph()
        self.detector = DeterministicAnomalyDetector(config=self.config)
        self.correlator = IncidentCorrelator(graph=self.graph, config=self.config)
        self.rca = RootCauseAnalyzer(graph=self.graph, config=self.config)

    def run(
        self,
        events: List[Dict[str, Any]],
        reference_time_utc: Optional[str] = None,
        tenant: str = "acme-payments",
    ) -> Dict[str, Any]:
        """Process approved events and return API-compatible fleet, egress, anomaly, and incident views."""
        valid_events: List[Dict[str, Any]] = []
        egress_records: List[Dict[str, Any]] = []

        sorted_events = sorted(events, key=lambda e: parse_utc_timestamp(e["timestamp_utc"]))
        for ev in sorted_events:
            is_valid, errors = validate_event(ev)
            sha256_hash = compute_event_sha256(ev)
            egress_records.append(
                {
                    "event_id": ev.get("event_id", "unknown"),
                    "event_type": ev.get("event_type", "unknown"),
                    "service_id": ev.get("service_id") or "n/a",
                    "collector_id": ev.get("collector_id", "unknown"),
                    "timestamp_utc": ev.get("timestamp_utc", ""),
                    "policy_version": ev.get("policy_version", "unknown"),
                    "approved_payload": ev,
                    "sha256_hash": sha256_hash,
                    "verification_status": "verified" if is_valid else "schema_rejected",
                    "validation_errors": errors,
                }
            )
            if is_valid:
                valid_events.append(ev)

        anomalies = self.detector.process_events(valid_events, reference_time_utc=reference_time_utc)
        groups = self.correlator.correlate(anomalies)
        incidents = [self.rca.analyze_incident(g, valid_events) for g in groups]

        fleet = self._build_fleet_view(valid_events, reference_time_utc=reference_time_utc, tenant=tenant)
        affected_services = sorted(
            {svc["service_id"] for inc in incidents for svc in inc["affected_services"]}
        )

        healthy_collectors = sum(1 for c in fleet if c["health_state"] == "healthy")
        unhealthy_collectors = len(fleet) - healthy_collectors

        return {
            "health": {
                "status": "degraded" if incidents else "healthy",
                "engine": "aegis-aiops-deterministic",
                "graph_engine": self.graph.backend_engine,
                "active_incidents": len(incidents),
                "healthy_collectors": healthy_collectors,
                "unhealthy_collectors": unhealthy_collectors,
                "anomaly_count": len(anomalies),
            },
            "dependency_graph": self.graph.to_dict(affected_services=affected_services),
            "events": valid_events,
            "egress_audit": egress_records,
            "fleet": fleet,
            "anomalies": [a.to_dict() for a in anomalies],
            "incidents": incidents,
        }

    def _build_fleet_view(
        self,
        events: List[Dict[str, Any]],
        reference_time_utc: Optional[str],
        tenant: str,
    ) -> List[Dict[str, Any]]:
        if not events:
            return []
        ref_dt = (
            parse_utc_timestamp(reference_time_utc)
            if reference_time_utc
            else parse_utc_timestamp(events[-1]["timestamp_utc"])
        )
        collectors: Dict[str, Dict[str, Any]] = {}

        for ev in events:
            cid = ev["collector_id"]
            entry = collectors.setdefault(
                cid,
                {
                    "collector_id": cid,
                    "tenant": tenant,
                    "region": ev["region"],
                    "service_id": ev.get("service_id"),
                    "health_state": "healthy",
                    "last_heartbeat": None,
                    "last_telemetry": ev["timestamp_utc"],
                    "queue_backlog": 0,
                    "collector_version": "unknown",
                    "cpu_percent": None,
                    "memory_percent": None,
                },
            )
            entry["last_telemetry"] = ev["timestamp_utc"]
            if ev["event_type"] == "heartbeat":
                entry["last_heartbeat"] = ev["timestamp_utc"]
                entry["health_state"] = ev["health_state"]
                entry["queue_backlog"] = ev.get("queue_backlog") or 0
                entry["collector_version"] = ev.get("collector_version") or "unknown"
                entry["cpu_percent"] = ev.get("cpu_percent")
                entry["memory_percent"] = ev.get("memory_percent")

        # Mark collectors offline if their last heartbeat exceeds timeout
        timeout = self.config.collector_offline_timeout_seconds
        for entry in collectors.values():
            if entry["last_heartbeat"]:
                age = (ref_dt - parse_utc_timestamp(entry["last_heartbeat"])).total_seconds()
                if age > timeout:
                    entry["health_state"] = "offline"

        return sorted(collectors.values(), key=lambda c: c["collector_id"])


def export_frontend_mock_bundle(output_path: Path) -> Dict[str, Any]:
    """Generate the frontend mock fixture bundle across all 8 simulated telemetry scenarios."""
    from .fixtures.telemetry_generator import build_all_scenarios

    scenarios = build_all_scenarios()
    bundle: Dict[str, Any] = {
        "mode": "mock",
        "generated_by": "aiops/pipeline.py",
        "scenarios": {},
    }

    for name, spec in scenarios.items():
        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(
            spec["events"],
            reference_time_utc=spec.get("reference_time_utc"),
            tenant=spec.get("tenant", "acme-payments"),
        )
        result["scenario_name"] = name
        result["scenario_label"] = spec["label"]
        result["scenario_description"] = spec["description"]
        bundle["scenarios"][name] = result

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return bundle


if __name__ == "__main__":
    default_out = Path(__file__).resolve().parent.parent / "frontend" / "src" / "fixtures" / "mockApiData.json"
    export_frontend_mock_bundle(default_out)
    print(f"Exported deterministic mock bundle to {default_out}")
