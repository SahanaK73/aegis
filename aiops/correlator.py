"""Incident correlation engine grouping related anomalies by time window and service dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .anomaly_detector import AnomalyRecord, parse_utc_timestamp
from .config import AIOpsConfig, DEFAULT_CONFIG
from .dependency_graph import ServiceDependencyGraph


@dataclass
class CorrelatedIncidentGroup:
    """Intermediate correlated group of anomalies prior to RCA hypothesis ranking."""

    group_id: str
    first_observed_utc: str
    last_observed_utc: str
    anomalies: List[AnomalyRecord] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    dependency_paths: List[str] = field(default_factory=list)
    severity: str = "warning"


class IncidentCorrelator:
    """Groups related anomalies using time windows and dependency graph relationships."""

    def __init__(
        self,
        graph: Optional[ServiceDependencyGraph] = None,
        config: Optional[AIOpsConfig] = None,
    ) -> None:
        self.graph = graph or ServiceDependencyGraph()
        self.config = config or DEFAULT_CONFIG

    def correlate(self, anomalies: List[AnomalyRecord]) -> List[CorrelatedIncidentGroup]:
        """Group anomalies into unified incidents so single spikes do not create alert storms."""
        if not anomalies:
            return []

        ordered = sorted(anomalies, key=lambda a: parse_utc_timestamp(a.timestamp_utc))
        groups: List[CorrelatedIncidentGroup] = []

        for anom in ordered:
            anom_dt = parse_utc_timestamp(anom.timestamp_utc)
            anom_service = self.graph.normalize_service_id(anom.service_id)
            matched_group: Optional[CorrelatedIncidentGroup] = None

            for group in groups:
                group_last_dt = parse_utc_timestamp(group.last_observed_utc)
                time_delta = abs((anom_dt - group_last_dt).total_seconds())
                if time_delta > self.config.correlation_window_seconds:
                    continue

                # Keep isolated auth-failure or collector-offline alerts grouped with
                # same-service or dependency-connected incidents only when they share
                # the same service or a graph dependency path.
                same_collector = any(a.collector_id == anom.collector_id for a in group.anomalies)
                graph_related = any(
                    self.graph.are_related(anom_service, svc) for svc in group.affected_services
                )

                # Prevent unrelated auth_failure_summary from merging into an infra metric incident
                # unless on the exact same service.
                group_has_only_auth = all(a.event_type == "auth_failure_summary" for a in group.anomalies)
                anom_is_auth = anom.event_type == "auth_failure_summary"
                if anom_is_auth != group_has_only_auth:
                    same_service = anom_service in group.affected_services
                    if not same_service:
                        continue

                if same_collector or graph_related:
                    matched_group = group
                    break

            if matched_group is None:
                group_id = f"INC-{len(groups) + 1:04d}"
                matched_group = CorrelatedIncidentGroup(
                    group_id=group_id,
                    first_observed_utc=anom.timestamp_utc,
                    last_observed_utc=anom.timestamp_utc,
                    anomalies=[anom],
                    affected_services=[anom_service],
                    severity=anom.severity,
                )
                groups.append(matched_group)
            else:
                matched_group.anomalies.append(anom)
                if anom_dt > parse_utc_timestamp(matched_group.last_observed_utc):
                    matched_group.last_observed_utc = anom.timestamp_utc
                if anom_service not in matched_group.affected_services:
                    matched_group.affected_services.append(anom_service)
                if anom.severity == "critical":
                    matched_group.severity = "critical"

        # Finalize dependency paths and canonical ordering
        for group in groups:
            group.dependency_paths = self.graph.dependency_paths_for(group.affected_services)

        return groups
