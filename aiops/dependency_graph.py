"""NetworkX-backed service dependency graph for the Aegis payment architecture.

Simulated payment architecture:
    API Gateway -> Payment Service -> Database
    Network Service -> Payment Service

Direction convention:
    Edge (A -> B) means service A depends on service B (or feeds directly into B
    in the operational request/network path). Specifically:
    - api-gateway -> payment-service -> database
    - network-service -> payment-service

For root-cause propagation:
    - Database failures propagate upstream to Payment Service and API Gateway.
    - Network Service failures impact Payment Service and API Gateway.
    - Payment Service failures impact API Gateway.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import networkx as nx  # type: ignore

    USING_NETWORKX = True
except ImportError:  # pragma: no cover - offline fallback with identical DiGraph API
    USING_NETWORKX = False
    nx = None


class _FallbackDiGraph:
    """Minimal NetworkX-compatible DiGraph fallback when networkx is unavailable."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._succ: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._pred: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def add_node(self, node: str, **attrs: Any) -> None:
        self._nodes.setdefault(node, {}).update(attrs)
        self._succ.setdefault(node, {})
        self._pred.setdefault(node, {})

    def add_edge(self, u: str, v: str, **attrs: Any) -> None:
        self.add_node(u)
        self.add_node(v)
        self._succ[u][v] = dict(attrs)
        self._pred[v][u] = dict(attrs)

    def has_node(self, node: str) -> bool:
        return node in self._nodes

    def nodes(self, data: bool = False):
        if data:
            return list(self._nodes.items())
        return list(self._nodes.keys())

    def edges(self, data: bool = False):
        result = []
        for u, nbrs in self._succ.items():
            for v, attrs in nbrs.items():
                result.append((u, v, attrs) if data else (u, v))
        return result

    def successors(self, node: str) -> List[str]:
        return list(self._succ.get(node, {}).keys())

    def predecessors(self, node: str) -> List[str]:
        return list(self._pred.get(node, {}).keys())


def _bfs(start: str, neighbor_fn) -> Set[str]:
    visited: Set[str] = set()
    queue = deque([start])
    while queue:
        curr = queue.popleft()
        for nxt in neighbor_fn(curr):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return visited


def _shortest_path(graph: Any, source: str, target: str) -> Optional[List[str]]:
    if source == target:
        return [source]
    if USING_NETWORKX:
        try:
            return list(nx.shortest_path(graph, source=source, target=target))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    visited = {source}
    queue = deque([[source]])
    while queue:
        path = queue.popleft()
        for nxt in graph.successors(path[-1]):
            if nxt == target:
                return path + [nxt]
            if nxt not in visited:
                visited.add(nxt)
                queue.append(path + [nxt])
    return None


class ServiceDependencyGraph:
    """Directed dependency graph modeling Aegis payment infrastructure."""

    SERVICE_METADATA: Dict[str, Dict[str, str]] = {
        "api-gateway": {
            "label": "API Gateway",
            "tier": "edge",
            "role": "External API ingress and request routing",
        },
        "payment-service": {
            "label": "Payment Service",
            "tier": "application",
            "role": "Core payment orchestration and transaction authorization",
        },
        "database": {
            "label": "Database",
            "tier": "data",
            "role": "Primary transactional ledger datastore",
        },
        "network-service": {
            "label": "Network Service",
            "tier": "infrastructure",
            "role": "Internal mesh routing and packet transport for payment traffic",
        },
    }

    DEFAULT_EDGES: List[Tuple[str, str, str]] = [
        ("api-gateway", "payment-service", "routes_to"),
        ("payment-service", "database", "queries"),
        ("network-service", "payment-service", "transports_for"),
    ]

    def __init__(self) -> None:
        self.graph = nx.DiGraph() if USING_NETWORKX else _FallbackDiGraph()
        for service_id, meta in self.SERVICE_METADATA.items():
            self.graph.add_node(service_id, **meta)
        for src, dst, relation in self.DEFAULT_EDGES:
            self.graph.add_edge(src, dst, relation=relation)

    @property
    def backend_engine(self) -> str:
        return "networkx" if USING_NETWORKX else "fallback-digraph"

    def normalize_service_id(self, service_id: str) -> str:
        """Normalize display names or slug variants to canonical service IDs."""
        mapping = {
            "api gateway": "api-gateway",
            "api-gateway": "api-gateway",
            "payment service": "payment-service",
            "payment-service": "payment-service",
            "database": "database",
            "db": "database",
            "network service": "network-service",
            "network-service": "network-service",
        }
        return mapping.get(service_id.strip().lower(), service_id.strip().lower())

    def label_for(self, service_id: str) -> str:
        sid = self.normalize_service_id(service_id)
        meta = self.SERVICE_METADATA.get(sid)
        return meta["label"] if meta else sid

    def impacted_by(self, root_service: str) -> Set[str]:
        """Return services that can be degraded when `root_service` degrades.

        - database -> impacts payment-service, api-gateway (reverse of calls)
        - network-service -> impacts payment-service, api-gateway
        - payment-service -> impacts api-gateway
        """
        sid = self.normalize_service_id(root_service)
        if not self.graph.has_node(sid):
            return set()

        impacted: Set[str] = set()
        if sid == "network-service":
            # Network Service feeds into Payment Service, which serves API Gateway.
            for nxt in self.graph.successors(sid):
                impacted.add(nxt)
                impacted.update(_bfs(nxt, self.graph.predecessors))
            impacted.discard(sid)
            return impacted

        # For request-path dependencies (api-gateway -> payment-service -> database),
        # failures propagate backward along predecessors (except network-service).
        queue = deque([sid])
        while queue:
            curr = queue.popleft()
            for pred in self.graph.predecessors(curr):
                if pred == "network-service":
                    continue
                if pred not in impacted and pred != sid:
                    impacted.add(pred)
                    queue.append(pred)
        return impacted

    def root_contributors_for(self, service_id: str) -> Set[str]:
        """Return services whose degradation could explain symptoms on `service_id`."""
        sid = self.normalize_service_id(service_id)
        if not self.graph.has_node(sid):
            return set()
        contributors: Set[str] = set()
        for candidate in self.graph.nodes():
            if candidate != sid and sid in self.impacted_by(candidate):
                contributors.add(candidate)
        return contributors

    def are_related(self, service_a: str, service_b: str) -> bool:
        """Return True if two services share a direct or transitive dependency relationship."""
        a = self.normalize_service_id(service_a)
        b = self.normalize_service_id(service_b)
        if a == b:
            return True
        if not (self.graph.has_node(a) and self.graph.has_node(b)):
            return False
        if b in self.impacted_by(a) or a in self.impacted_by(b):
            return True
        # Also related if they share a common impacted service (e.g. network-service & database -> payment-service)
        return bool(self.impacted_by(a) & self.impacted_by(b))

    def dependency_paths_for(self, affected_services: Iterable[str]) -> List[str]:
        """Build human-readable dependency paths connecting the affected services."""
        affected = {self.normalize_service_id(s) for s in affected_services}
        paths: List[str] = []

        # Check canonical request path: API Gateway -> Payment Service -> Database
        req_chain = ["api-gateway", "payment-service", "database"]
        present_req = [s for s in req_chain if s in affected]
        if len(present_req) >= 2:
            full_path = _shortest_path(self.graph, present_req[0], present_req[-1])
            if full_path:
                paths.append(" -> ".join(self.label_for(n) for n in full_path))

        # Check network transport path: Network Service -> Payment Service (-> API Gateway if impacted)
        if "network-service" in affected:
            if "payment-service" in affected and "api-gateway" in affected:
                paths.append("Network Service -> Payment Service <- API Gateway")
            elif "payment-service" in affected:
                paths.append("Network Service -> Payment Service")
            elif "api-gateway" in affected:
                paths.append("Network Service -> Payment Service <- API Gateway")

        if not paths and affected:
            # Single affected service or isolated node
            ordered = sorted(affected)
            paths.append(" -> ".join(self.label_for(s) for s in ordered))

        return paths

    def to_dict(self, affected_services: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Export graph structure for dashboard rendering."""
        affected_set = {self.normalize_service_id(s) for s in (affected_services or [])}
        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            nodes.append(
                {
                    "id": node_id,
                    "label": attrs.get("label", node_id),
                    "tier": attrs.get("tier", "unknown"),
                    "role": attrs.get("role", ""),
                    "affected": node_id in affected_set,
                }
            )
        edges = []
        for src, dst, attrs in self.graph.edges(data=True):
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "relation": attrs.get("relation", "depends_on"),
                    "active_path": src in affected_set and dst in affected_set,
                }
            )
        return {
            "engine": self.backend_engine,
            "nodes": nodes,
            "edges": edges,
        }
