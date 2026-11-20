"""Deterministic, evidence-backed Root-Cause Analysis (RCA) engine.

Strict epistemic guarantees:
- Never invents evidence: every evidence item is derived from observed approved telemetry.
- Never claims a root cause is certain: every candidate is explicitly marked as a hypothesis
  with calibrated confidence (capped <= 0.90) and a transparent ranking explanation.
- Zero LLM dependency for detection, correlation, or root-cause proof.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .anomaly_detector import AnomalyRecord, parse_utc_timestamp
from .config import AIOpsConfig, DEFAULT_CONFIG
from .correlator import CorrelatedIncidentGroup
from .dependency_graph import ServiceDependencyGraph


class RootCauseAnalyzer:
    """Produces ranked, evidence-backed root-cause hypotheses for correlated incidents."""

    RECOMMENDED_ACTIONS: Dict[Tuple[str, str], Dict[str, str]] = {
        ("database", "cpu_percent"): {
            "action": "Inspect slow payment queries, check connection pool saturation, and approve read-replica failover or query throttling on Database.",
            "rollback_note": "Revert query throttling or restore primary read routing once Database CPU drops below 70% for 10 minutes.",
        },
        ("database", "memory_percent"): {
            "action": "Review Database buffer pool / cache allocation and approve a controlled connection drain or vertical memory scale-up.",
            "rollback_note": "Restore previous memory limits and re-enable drained connections after memory stabilizes below 75%.",
        },
        ("network-service", "packet_loss_percent"): {
            "action": "Inspect mesh NIC/switch error counters on Network Service and approve traffic rerouting to the secondary network path.",
            "rollback_note": "Shift traffic back to the primary network path after packet loss remains <0.5% for 15 minutes.",
        },
        ("payment-service", "latency_ms"): {
            "action": "Review Payment Service worker thread saturation and downstream timeouts; approve circuit-breaker tuning or pod scale-out.",
            "rollback_note": "Scale replicas back to baseline count and restore default circuit-breaker thresholds once p95 latency <180ms.",
        },
        ("api-gateway", "latency_ms"): {
            "action": "Check API Gateway upstream timeout budgets and rate-limit policies; approve temporary burst rate-limiting.",
            "rollback_note": "Remove temporary rate-limit override after upstream Payment Service latency normalizes.",
        },
        ("api-gateway", "auth_failure_count"): {
            "action": "Review aggregated auth_failure_summary codes on API Gateway and approve temporary IP/client-class rate limiting.",
            "rollback_note": "Lift temporary auth rate limits once failed login summary counts return to baseline.",
        },
        ("collector", "collector_heartbeat_gap_seconds"): {
            "action": "Verify collector daemon liveness and outbound egress connectivity on the affected host; approve collector service restart.",
            "rollback_note": "No destructive state change; revert to previous collector config snapshot if restart fails.",
        },
    }

    def __init__(
        self,
        graph: Optional[ServiceDependencyGraph] = None,
        config: Optional[AIOpsConfig] = None,
    ) -> None:
        self.graph = graph or ServiceDependencyGraph()
        self.config = config or DEFAULT_CONFIG

    def analyze_incident(
        self,
        group: CorrelatedIncidentGroup,
        all_events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build a complete, evidence-backed incident record with up to 3 ranked hypotheses."""
        anomalies = sorted(group.anomalies, key=lambda a: parse_utc_timestamp(a.timestamp_utc))
        first_dt = parse_utc_timestamp(group.first_observed_utc)

        # Group anomalies by normalized service_id
        by_service: Dict[str, List[AnomalyRecord]] = defaultdict(list)
        for anom in anomalies:
            by_service[self.graph.normalize_service_id(anom.service_id)].append(anom)

        # Gather normal/healthy telemetry in the same time window for contradicting evidence checks
        window_start = first_dt.timestamp() - self.config.correlation_window_seconds
        window_end = parse_utc_timestamp(group.last_observed_utc).timestamp() + 60
        healthy_observations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        anomalous_event_ids = {eid for a in anomalies for eid in a.supporting_event_ids}

        for ev in all_events:
            ev_ts = parse_utc_timestamp(ev["timestamp_utc"]).timestamp()
            if ev.get("event_type") == "heartbeat" or not ev.get("service_id"):
                continue  # collector-level events carry no service evidence
            if window_start <= ev_ts <= window_end and ev["event_id"] not in anomalous_event_ids:
                sid = self.graph.normalize_service_id(ev["service_id"])
                healthy_observations[sid].append(ev)

        # Candidate services: all affected services plus any direct upstream dependency
        candidate_services = list(by_service.keys())
        for svc in list(by_service.keys()):
            for upstream in self.graph.root_contributors_for(svc):
                if upstream not in candidate_services:
                    candidate_services.append(upstream)

        scored_hypotheses: List[Dict[str, Any]] = []
        for candidate in candidate_services:
            svc_anoms = by_service.get(candidate, [])
            impacted_affected = [
                s for s in group.affected_services if s in self.graph.impacted_by(candidate)
            ]

            # Skip upstream services that neither have anomalies nor explain multiple affected services
            if not svc_anoms and not impacted_affected:
                continue

            score = 0.0
            reasons: List[str] = []

            # 1. Direct observed anomalies on the candidate service
            if svc_anoms:
                crit_count = sum(1 for a in svc_anoms if a.severity == "critical")
                warn_count = sum(1 for a in svc_anoms if a.severity == "warning")
                score += 0.38 + min(0.18, crit_count * 0.09 + warn_count * 0.04)
                metrics_str = ", ".join(sorted({a.metric_name for a in svc_anoms}))
                reasons.append(
                    f"Direct sustained anomalies observed on {self.graph.label_for(candidate)} ({metrics_str})."
                )
            else:
                score += 0.12
                reasons.append(
                    f"{self.graph.label_for(candidate)} is an upstream dependency of affected service(s), though no direct anomaly was observed on it."
                )

            # 2. Dependency topology propagation weight
            if impacted_affected:
                score += min(0.28, 0.14 * len(impacted_affected))
                impacted_labels = ", ".join(self.graph.label_for(s) for s in impacted_affected)
                reasons.append(
                    f"Dependency graph shows {self.graph.label_for(candidate)} can propagate degradation to {impacted_labels}."
                )

            # 3. Temporal precedence (earliest anomaly observed)
            if svc_anoms:
                earliest_svc_dt = min(parse_utc_timestamp(a.timestamp_utc) for a in svc_anoms)
                lag_sec = (earliest_svc_dt - first_dt).total_seconds()
                if lag_sec <= 30:
                    score += 0.12
                    reasons.append(
                        f"Among the earliest observed deviations in this incident (t+{int(lag_sec)}s from incident onset)."
                    )
                elif lag_sec <= 90:
                    score += 0.05
                    reasons.append(
                        f"Deviated {int(lag_sec)}s after initial incident onset."
                    )

            # 4. Contradicting evidence penalty (healthy metrics on candidate during window)
            contradicting: List[Dict[str, Any]] = []
            normal_metric_evs = [
                ev for ev in healthy_observations.get(candidate, []) if ev["event_type"] == "metric"
            ]
            if not svc_anoms and normal_metric_evs:
                score = max(0.10, score - 0.15)
                sample_ev = normal_metric_evs[-1]
                contradicting.append(
                    {
                        "event_id": sample_ev["event_id"],
                        "timestamp_utc": sample_ev["timestamp_utc"],
                        "service_id": candidate,
                        "summary": (
                            f"Observed normal {sample_ev['metric_name']}="
                            f"{sample_ev['metric_value']} {sample_ev['unit']} on "
                            f"{self.graph.label_for(candidate)} during the incident window."
                        ),
                    }
                )
                reasons.append(
                    f"Contradicting telemetry: healthy metric readings were recorded on {self.graph.label_for(candidate)} during the window."
                )
            elif svc_anoms:
                # Check if other metrics on the same service stayed normal (useful scoping context)
                anom_metrics = {a.metric_name for a in svc_anoms}
                other_healthy = [
                    ev for ev in normal_metric_evs if ev["metric_name"] not in anom_metrics
                ]
                if other_healthy:
                    sample_ev = other_healthy[-1]
                    contradicting.append(
                        {
                            "event_id": sample_ev["event_id"],
                            "timestamp_utc": sample_ev["timestamp_utc"],
                            "service_id": candidate,
                            "summary": (
                                f"{sample_ev['metric_name']} remained within normal range "
                                f"({sample_ev['metric_value']} {sample_ev['unit']}) on "
                                f"{self.graph.label_for(candidate)}."
                            ),
                        }
                    )

            # Cap confidence at 0.90 to enforce epistemic humility (hypothesis, never certainty)
            confidence = round(min(0.90, max(0.10, score)), 2)

            # Build supporting evidence strictly from observed anomalies
            supporting: List[Dict[str, Any]] = []
            for a in svc_anoms[:4]:
                supporting.append(
                    {
                        "event_id": a.event_id,
                        "timestamp_utc": a.timestamp_utc,
                        "service_id": candidate,
                        "metric_name": a.metric_name,
                        "metric_value": a.metric_value,
                        "unit": a.unit,
                        "detection_mode": a.detection_mode,
                        "summary": a.reason,
                    }
                )
            for dep_svc in impacted_affected:
                dep_anoms = by_service.get(dep_svc, [])
                if dep_anoms:
                    first_dep = dep_anoms[0]
                    supporting.append(
                        {
                            "event_id": first_dep.event_id,
                            "timestamp_utc": first_dep.timestamp_utc,
                            "service_id": dep_svc,
                            "metric_name": first_dep.metric_name,
                            "metric_value": first_dep.metric_value,
                            "unit": first_dep.unit,
                            "detection_mode": first_dep.detection_mode,
                            "summary": (
                                f"Downstream impact observed on {self.graph.label_for(dep_svc)}: "
                                f"{first_dep.metric_name}={first_dep.metric_value} {first_dep.unit}."
                            ),
                        }
                    )

            primary_metric = svc_anoms[0].metric_name if svc_anoms else "upstream_dependency"
            title = self._hypothesis_title(candidate, primary_metric, bool(svc_anoms))
            scored_hypotheses.append(
                {
                    "service_id": candidate,
                    "service_label": self.graph.label_for(candidate),
                    "hypothesis": title,
                    "is_hypothesis": True,
                    "confidence_score": confidence,
                    "confidence_label": self._confidence_label(confidence),
                    "ranking_explanation": " ".join(reasons),
                    "supporting_evidence": supporting,
                    "contradicting_evidence": contradicting,
                    "primary_metric": primary_metric,
                }
            )

        # Sort deterministically by confidence desc, then direct anomaly count desc, then service_id
        scored_hypotheses.sort(
            key=lambda h: (-h["confidence_score"], -len(h["supporting_evidence"]), h["service_id"])
        )
        top_hypotheses = scored_hypotheses[: self.config.max_root_cause_hypotheses]
        for idx, hyp in enumerate(top_hypotheses, start=1):
            hyp["rank"] = idx

        # Aggregate incident-level supporting & contradicting evidence (deduplicated by event_id + summary)
        incident_supporting = self._dedup_evidence(
            [ev for h in top_hypotheses for ev in h["supporting_evidence"]]
        )
        incident_contradicting = self._dedup_evidence(
            [ev for h in top_hypotheses for ev in h["contradicting_evidence"]]
        )

        # Recommended human-approved next action based on top-ranked hypothesis
        top = top_hypotheses[0] if top_hypotheses else None
        rec = self._recommended_action_for(top)

        # Deduplicated metric deviation summary
        deviations_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for a in anomalies:
            key = (self.graph.normalize_service_id(a.service_id), a.metric_name)
            existing = deviations_map.get(key)
            if existing is None or a.metric_value > existing["peak_value"]:
                deviations_map[key] = {
                    "service_id": key[0],
                    "service_label": self.graph.label_for(key[0]),
                    "metric_name": a.metric_name,
                    "peak_value": a.metric_value,
                    "unit": a.unit,
                    "severity": a.severity,
                    "detection_mode": a.detection_mode,
                    "consecutive_count": a.consecutive_count,
                    "baseline_mean": a.baseline_mean,
                    "threshold_used": a.threshold_used,
                    "event_id": a.event_id,
                }

        timeline = [
            {
                "timestamp_utc": a.timestamp_utc,
                "event_id": a.event_id,
                "service_id": self.graph.normalize_service_id(a.service_id),
                "service_label": self.graph.label_for(a.service_id),
                "severity": a.severity,
                "detection_mode": a.detection_mode,
                "summary": a.reason,
            }
            for a in anomalies
        ]

        return {
            "incident_id": group.group_id,
            "title": self._incident_title(group, top),
            "severity": group.severity,
            "status": "active",
            "first_observed_utc": group.first_observed_utc,
            "last_observed_utc": group.last_observed_utc,
            "affected_services": [
                {"service_id": s, "label": self.graph.label_for(s)} for s in group.affected_services
            ],
            "related_metric_deviations": list(deviations_map.values()),
            "dependency_path": group.dependency_paths,
            "timeline": timeline,
            "supporting_evidence": incident_supporting,
            "contradicting_evidence": incident_contradicting,
            "root_cause_hypotheses": top_hypotheses,
            "confidence_explanation": (
                top["ranking_explanation"]
                if top
                else "Insufficient evidence to rank a root-cause hypothesis."
            ),
            "recommended_action": {
                "action": rec["action"],
                "approval_required": True,
                "approval_status": "pending_human_approval",
                "rollback_note": rec["rollback_note"],
                "audit_records": [
                    {
                        "timestamp_utc": group.last_observed_utc,
                        "actor": "aegis-aiops-engine",
                        "decision": "proposed",
                        "note": "Deterministic RCA generated hypothesis-backed recommendation awaiting human approval.",
                    }
                ],
            },
        }

    def _hypothesis_title(self, service_id: str, metric_name: str, has_direct: bool) -> str:
        label = self.graph.label_for(service_id)
        if not has_direct:
            return f"Possible unobserved upstream degradation in {label}"
        metric_phrases = {
            "cpu_percent": f"Sustained CPU saturation on {label}",
            "memory_percent": f"Sustained memory pressure on {label}",
            "latency_ms": f"Elevated response latency on {label}",
            "packet_loss_percent": f"Network packet loss impacting {label}",
            "auth_failure_count": f"Repeated authentication failures targeting {label}",
            "collector_heartbeat_gap_seconds": f"Telemetry collector outage on {label}",
            "collector_health": f"Collector health degradation / queue backlog on {label}",
        }
        return metric_phrases.get(metric_name, f"Anomalous {metric_name} on {label}")

    def _confidence_label(self, score: float) -> str:
        if score >= 0.75:
            return "High-priority hypothesis (not confirmed)"
        if score >= 0.50:
            return "Moderate-priority hypothesis (not confirmed)"
        return "Low-priority hypothesis (needs verification)"

    def _incident_title(
        self, group: CorrelatedIncidentGroup, top_hypothesis: Optional[Dict[str, Any]]
    ) -> str:
        if len(group.affected_services) > 1 and top_hypothesis:
            return (
                f"Correlated Payment Path Degradation — Suspected "
                f"{top_hypothesis['service_label']} Contributor"
            )
        if top_hypothesis:
            return top_hypothesis["hypothesis"]
        return f"Infrastructure Anomaly ({group.group_id})"

    def _recommended_action_for(self, top: Optional[Dict[str, Any]]) -> Dict[str, str]:
        if not top:
            return {
                "action": "Collect additional telemetry and manually inspect affected hosts before making changes.",
                "rollback_note": "No automated changes applied; nothing to roll back.",
            }
        key = (top["service_id"], top["primary_metric"])
        if key in self.RECOMMENDED_ACTIONS:
            return self.RECOMMENDED_ACTIONS[key]
        if top["primary_metric"] in {"collector_heartbeat_gap_seconds", "collector_health"}:
            return self.RECOMMENDED_ACTIONS[("collector", "collector_heartbeat_gap_seconds")]
        return {
            "action": (
                f"Inspect live diagnostics and logs on {top['service_label']} for "
                f"{top['primary_metric']} before approving targeted mitigation."
            ),
            "rollback_note": f"Revert any manual configuration changes on {top['service_label']} if metrics do not improve within 10 minutes.",
        }

    @staticmethod
    def _dedup_evidence(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for item in items:
            key = (item.get("event_id"), item.get("summary"))
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out
