"""Comprehensive unit tests for the Aegis deterministic AIOps engine.

Runnable with either `python3 -m unittest discover -s aiops/tests -v` or `pytest aiops/tests`.
"""

from __future__ import annotations

import unittest

from aiops.anomaly_detector import DeterministicAnomalyDetector
from aiops.config import AIOpsConfig
from aiops.correlator import IncidentCorrelator
from aiops.dependency_graph import ServiceDependencyGraph
from aiops.fixtures.telemetry_generator import (
    _metric_event,
    build_all_scenarios,
    scenario_collector_offline,
    scenario_correlated_anomalies,
    scenario_high_cpu,
    scenario_normal_infrastructure,
    scenario_packet_loss,
    scenario_repeated_failed_logins,
)
from aiops.pipeline import AegisAIOpsPipeline
from aiops.schema import compute_event_sha256, validate_event, verify_event_hash


class TestAegisAIOpsEngine(unittest.TestCase):
    def test_all_eight_scenarios_conform_to_shared_event_contract(self) -> None:
        scenarios = build_all_scenarios()
        self.assertEqual(len(scenarios), 8)
        for name, spec in scenarios.items():
            self.assertGreater(len(spec["events"]), 0, f"Scenario {name} should have events")
            for ev in spec["events"]:
                is_valid, errors = validate_event(ev)
                self.assertTrue(is_valid, f"Scenario {name} event invalid: {errors}")
                digest = compute_event_sha256(ev)
                self.assertEqual(len(digest), 64)
                self.assertTrue(verify_event_hash(ev, digest))

    def test_normal_infrastructure_produces_zero_anomalies_and_incidents(self) -> None:
        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(scenario_normal_infrastructure()["events"])
        self.assertEqual(result["health"]["anomaly_count"], 0)
        self.assertEqual(result["health"]["active_incidents"], 0)
        self.assertEqual(result["health"]["healthy_collectors"], 4)
        self.assertEqual(result["health"]["unhealthy_collectors"], 0)

    def test_sustained_baseline_anomaly_requires_three_consecutive_deviations(self) -> None:
        detector = DeterministicAnomalyDetector(AIOpsConfig())
        # 6 healthy baseline points + only 2 transient spikes -> should NOT trigger sustained anomaly
        events = [
            _metric_event(i, "col-db-01", "database", "cpu_percent", 30.0 + (i % 2), "percent", i * 30, "db-01", "none")
            for i in range(6)
        ]
        events.append(_metric_event(10, "col-db-01", "database", "cpu_percent", 95.0, "percent", 180, "db-01", "none"))
        events.append(_metric_event(11, "col-db-01", "database", "cpu_percent", 96.0, "percent", 210, "db-01", "none"))

        transient_anoms = detector.process_events(events)
        self.assertEqual(len(transient_anoms), 0, "Two consecutive spikes must not trigger a sustained anomaly")

        # Add 3rd consecutive spike -> MUST trigger baseline-based sustained anomaly
        events.append(_metric_event(12, "col-db-01", "database", "cpu_percent", 97.0, "percent", 240, "db-01", "none"))
        detector2 = DeterministicAnomalyDetector(AIOpsConfig())
        sustained_anoms = detector2.process_events(events)
        self.assertEqual(len(sustained_anoms), 1)
        self.assertEqual(sustained_anoms[0].detection_mode, "baseline-based")
        self.assertTrue(sustained_anoms[0].sustained)
        self.assertEqual(sustained_anoms[0].consecutive_count, 3)
        self.assertIsNotNone(sustained_anoms[0].baseline_mean)
        self.assertIsNotNone(sustained_anoms[0].z_score)

    def test_cold_start_threshold_fallback_is_explicitly_labeled(self) -> None:
        detector = DeterministicAnomalyDetector(AIOpsConfig(min_baseline_samples=5))
        # Only 3 cold-start high CPU points (zero warm-up history) -> must use static threshold fallback
        cold_events = [
            _metric_event(1, "col-db-01", "database", "cpu_percent", 94.0, "percent", 0, "db-01", "none"),
            _metric_event(2, "col-db-01", "database", "cpu_percent", 95.5, "percent", 30, "db-01", "none"),
            _metric_event(3, "col-db-01", "database", "cpu_percent", 96.2, "percent", 60, "db-01", "none"),
        ]
        anomalies = detector.process_events(cold_events)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].detection_mode, "threshold-based")
        self.assertIsNone(anomalies[0].baseline_mean)
        self.assertEqual(anomalies[0].severity, "critical")

    def test_incident_grouping_prevents_separate_incidents_per_metric_spike(self) -> None:
        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(scenario_correlated_anomalies()["events"])
        # Multiple metrics across Database, Payment Service, and API Gateway must correlate into ONE incident
        self.assertGreaterEqual(len(result["anomalies"]), 5)
        self.assertEqual(len(result["incidents"]), 1)

        incident = result["incidents"][0]
        affected_ids = {s["service_id"] for s in incident["affected_services"]}
        self.assertEqual(affected_ids, {"database", "payment-service", "api-gateway"})
        self.assertIn("API Gateway -> Payment Service -> Database", incident["dependency_path"])

    def test_dependency_based_ranking_prioritizes_upstream_database(self) -> None:
        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(scenario_correlated_anomalies()["events"])
        incident = result["incidents"][0]
        hypotheses = incident["root_cause_hypotheses"]

        self.assertGreaterEqual(len(hypotheses), 2)
        self.assertLessEqual(len(hypotheses), 3)
        # Database is upstream and deviated earliest -> must be ranked #1
        self.assertEqual(hypotheses[0]["rank"], 1)
        self.assertEqual(hypotheses[0]["service_id"], "database")
        self.assertTrue(hypotheses[0]["is_hypothesis"])
        self.assertLessEqual(hypotheses[0]["confidence_score"], 0.90)
        self.assertIn("not confirmed", hypotheses[0]["confidence_label"].lower())

    def test_dependency_graph_network_service_propagation_and_ranking(self) -> None:
        graph = ServiceDependencyGraph()
        self.assertEqual(graph.impacted_by("network-service"), {"payment-service", "api-gateway"})
        self.assertEqual(graph.impacted_by("database"), {"payment-service", "api-gateway"})
        self.assertEqual(graph.impacted_by("payment-service"), {"api-gateway"})

        # Build a correlated packet-loss -> payment latency cascade
        events = list(scenario_packet_loss()["events"])
        events.extend(
            [
                _metric_event(901, "col-pay-01", "payment-service", "latency_ms", 340.0, "ms", 210, "pay-pod-01", "database"),
                _metric_event(902, "col-pay-01", "payment-service", "latency_ms", 480.0, "ms", 240, "pay-pod-01", "database"),
                _metric_event(903, "col-pay-01", "payment-service", "latency_ms", 590.0, "ms", 270, "pay-pod-01", "database"),
            ]
        )
        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(events)
        self.assertEqual(len(result["incidents"]), 1)
        top_hyp = result["incidents"][0]["root_cause_hypotheses"][0]
        self.assertEqual(top_hyp["service_id"], "network-service")
        self.assertIn("Network Service -> Payment Service", result["incidents"][0]["dependency_path"])

    def test_evidence_generation_uses_only_observed_events_and_includes_contradicting_evidence(self) -> None:
        spec = scenario_high_cpu()
        input_event_ids = {ev["event_id"] for ev in spec["events"]}

        pipeline = AegisAIOpsPipeline()
        result = pipeline.run(spec["events"])
        self.assertEqual(len(result["incidents"]), 1)
        inc = result["incidents"][0]

        # Every supporting and contradicting evidence item must reference an actual observed event_id
        self.assertGreater(len(inc["supporting_evidence"]), 0)
        for item in inc["supporting_evidence"]:
            self.assertIn(item["event_id"], input_event_ids)
        self.assertGreater(len(inc["contradicting_evidence"]), 0)
        for item in inc["contradicting_evidence"]:
            self.assertIn(item["event_id"], input_event_ids)

        # Human-approved remediation metadata must be present
        rec = inc["recommended_action"]
        self.assertTrue(rec["approval_required"])
        self.assertEqual(rec["approval_status"], "pending_human_approval")
        self.assertTrue(len(rec["rollback_note"]) > 10)

    def test_auth_failure_and_collector_offline_scenarios(self) -> None:
        auth_res = AegisAIOpsPipeline().run(scenario_repeated_failed_logins()["events"])
        self.assertEqual(len(auth_res["incidents"]), 1)
        self.assertEqual(auth_res["incidents"][0]["severity"], "critical")

        off_spec = scenario_collector_offline()
        off_res = AegisAIOpsPipeline().run(
            off_spec["events"], reference_time_utc=off_spec["reference_time_utc"]
        )
        self.assertEqual(len(off_res["incidents"]), 1)
        offline_collectors = [c for c in off_res["fleet"] if c["health_state"] == "offline"]
        self.assertEqual(len(offline_collectors), 1)
        self.assertEqual(offline_collectors[0]["collector_id"], "col-net-01")


if __name__ == "__main__":
    unittest.main()
