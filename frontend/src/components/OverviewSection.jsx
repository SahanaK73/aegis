import React from 'react';
import { EmptyState } from './StateBanner';

const NODE_POSITIONS = {
  'api-gateway': { x: 110, y: 62 },
  'payment-service': { x: 370, y: 105 },
  database: { x: 640, y: 105 },
  'network-service': { x: 110, y: 152 },
};

export default function OverviewSection({ health, dependencyGraph, anomalies, incidents, onOpenIncidents }) {
  const nodes = dependencyGraph?.nodes || [];
  const edges = dependencyGraph?.edges || [];

  return (
    <section aria-label="Overview">
      <div className="kpi-grid">
        <div className="card">
          <div className="kpi-label">Active Incidents</div>
          <div
            className="kpi-value"
            data-testid="kpi-active-incidents"
            style={{ color: health.active_incidents > 0 ? '#fca5a5' : '#86efac' }}
          >
            {health.active_incidents}
          </div>
          <div className="kpi-sub">Correlated across time &amp; service graph</div>
        </div>

        <div className="card">
          <div className="kpi-label">Healthy Collectors</div>
          <div
            className="kpi-value"
            data-testid="kpi-healthy-collectors"
            style={{ color: '#86efac' }}
          >
            {health.healthy_collectors}
          </div>
          <div className="kpi-sub">Reporting heartbeats within timeout</div>
        </div>

        <div className="card">
          <div className="kpi-label">Unhealthy Collectors</div>
          <div
            className="kpi-value"
            data-testid="kpi-unhealthy-collectors"
            style={{ color: health.unhealthy_collectors > 0 ? '#fcd34d' : '#94a3b8' }}
          >
            {health.unhealthy_collectors}
          </div>
          <div className="kpi-sub">Degraded, unhealthy, or offline</div>
        </div>

        <div className="card">
          <div className="kpi-label">Anomaly Count</div>
          <div
            className="kpi-value"
            data-testid="kpi-anomaly-count"
            style={{ color: health.anomaly_count > 0 ? '#7dd3fc' : '#94a3b8' }}
          >
            {health.anomaly_count}
          </div>
          <div className="kpi-sub">Sustained baseline &amp; threshold detections</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
          <h2 className="card-title" style={{ margin: 0 }}>
            Payment Architecture Dependency Graph
          </h2>
          <span className="mono" style={{ fontSize: 12, color: '#94a3b8' }}>
            API Gateway → Payment Service → Database | Network Service → Payment Service
          </span>
        </div>

        <svg className="graph-svg" viewBox="0 0 760 210" role="img" aria-label="Service Dependency Graph">
          <defs>
            <marker id="arrow-normal" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0,0 L0,6 L9,3 z" fill="#64748b" />
            </marker>
            <marker id="arrow-active" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0,0 L0,6 L9,3 z" fill="#f87171" />
            </marker>
          </defs>

          {edges.map((edge) => {
            const src = NODE_POSITIONS[edge.source];
            const dst = NODE_POSITIONS[edge.target];
            if (!src || !dst) return null;
            return (
              <line
                key={`${edge.source}-${edge.target}`}
                x1={src.x + 80}
                y1={src.y}
                x2={dst.x - 86}
                y2={dst.y}
                stroke={edge.active_path ? '#f87171' : '#475569'}
                strokeWidth={edge.active_path ? 3 : 2}
                markerEnd={edge.active_path ? 'url(#arrow-active)' : 'url(#arrow-normal)'}
              />
            );
          })}

          {nodes.map((node) => {
            const pos = NODE_POSITIONS[node.id] || { x: 380, y: 105 };
            return (
              <g key={node.id} transform={`translate(${pos.x - 80}, ${pos.y - 24})`}>
                <rect
                  width="160"
                  height="48"
                  rx="8"
                  fill={node.affected ? 'rgba(239, 68, 68, 0.2)' : '#1e293b'}
                  stroke={node.affected ? '#ef4444' : '#334155'}
                  strokeWidth={node.affected ? 2 : 1.5}
                />
                <text x="80" y="21" textAnchor="middle" fill="#f8fafc" fontSize="13" fontWeight="700">
                  {node.label}
                </text>
                <text
                  x="80"
                  y="37"
                  textAnchor="middle"
                  fill={node.affected ? '#fca5a5' : '#94a3b8'}
                  fontSize="11"
                >
                  {node.affected ? 'AFFECTED' : node.tier.toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 className="card-title" style={{ margin: 0 }}>
            Recent Deterministic Anomalies
          </h2>
          {incidents.length > 0 && (
            <button type="button" className="btn btn-primary" onClick={onOpenIncidents}>
              Inspect Correlated Incidents ({incidents.length})
            </button>
          )}
        </div>

        {anomalies.length === 0 ? (
          <EmptyState
            title="No anomalies detected"
            detail="All monitored CPU, memory, latency, packet-loss, heartbeat, and auth metrics are within normal ranges."
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Service</th>
                  <th>Metric</th>
                  <th>Value</th>
                  <th>Detection Mode</th>
                  <th>Severity</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {anomalies.map((a) => (
                  <tr key={a.anomaly_id}>
                    <td className="mono">{a.timestamp_utc}</td>
                    <td>{a.service_id}</td>
                    <td className="mono">{a.metric_name}</td>
                    <td className="mono">
                      {a.metric_value} {a.unit}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          a.detection_mode === 'baseline-based' ? 'badge-baseline' : 'badge-threshold'
                        }`}
                      >
                        {a.detection_mode}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                    </td>
                    <td>{a.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
