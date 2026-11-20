import React, { useState } from 'react';
import { EmptyState } from './StateBanner';

export default function IncidentsSection({ incidents, onGoToRemediation }) {
  const [selectedId, setSelectedId] = useState(incidents[0]?.incident_id || null);

  if (!incidents || incidents.length === 0) {
    return (
      <EmptyState
        title="No active incidents"
        detail="No correlated incidents were detected for the current telemetry window."
      />
    );
  }

  const activeIncident =
    incidents.find((inc) => inc.incident_id === selectedId) || incidents[0];

  return (
    <section aria-label="Incidents" className="incident-layout">
      <div className="card">
        <h2 className="card-title">Correlated Incidents ({incidents.length})</h2>
        {incidents.map((inc) => (
          <div
            key={inc.incident_id}
            role="button"
            tabIndex={0}
            className={`incident-item ${inc.incident_id === activeIncident.incident_id ? 'selected' : ''}`}
            onClick={() => setSelectedId(inc.incident_id)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') setSelectedId(inc.incident_id);
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span className="mono" style={{ fontSize: 12, color: '#94a3b8' }}>
                {inc.incident_id}
              </span>
              <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>{inc.title}</div>
            <div className="mono" style={{ fontSize: 11, color: '#94a3b8' }}>
              First observed: {inc.first_observed_utc}
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <span className="mono" style={{ fontSize: 12, color: '#94a3b8' }}>
              {activeIncident.incident_id} · First observed {activeIncident.first_observed_utc}
            </span>
            <h2 style={{ margin: '4px 0 8px 0', fontSize: 20 }}>{activeIncident.title}</h2>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className={`badge badge-${activeIncident.severity}`}>
              {activeIncident.severity}
            </span>
            {onGoToRemediation && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onGoToRemediation(activeIncident.incident_id)}
              >
                Review Remediation
              </button>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
          {activeIncident.affected_services.map((svc) => (
            <span key={svc.service_id} className="badge badge-critical">
              Affected: {svc.label}
            </span>
          ))}
          {activeIncident.dependency_path.map((pathStr) => (
            <span key={pathStr} className="badge badge-baseline mono">
              Path: {pathStr}
            </span>
          ))}
        </div>

        <h3 className="card-title">Ranked Root-Cause Hypotheses (Deterministic, Non-LLM)</h3>
        {activeIncident.root_cause_hypotheses.map((hyp) => (
          <div key={`${activeIncident.incident_id}-h-${hyp.rank}`} className="hypothesis-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
              <div style={{ fontWeight: 700, fontSize: 15 }}>
                #{hyp.rank} Hypothesis: {hyp.hypothesis}
              </div>
              <span className="badge badge-warning">
                Score {Math.round(hyp.confidence_score * 100)}% — {hyp.confidence_label}
              </span>
            </div>
            <p style={{ margin: '8px 0', fontSize: 13, color: '#cbd5e1' }}>
              <strong>Ranking Explanation:</strong> {hyp.ranking_explanation}
            </p>

            {hyp.supporting_evidence.length > 0 && (
              <div className="evidence-box">
                <strong style={{ color: '#86efac' }}>Supporting Evidence:</strong>
                <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                  {hyp.supporting_evidence.map((ev, idx) => (
                    <li key={`${ev.event_id}-${idx}`} style={{ marginBottom: 4 }}>
                      <span className="mono">[{ev.event_id}]</span> {ev.summary}{' '}
                      <span className="badge badge-baseline">{ev.detection_mode}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {hyp.contradicting_evidence && hyp.contradicting_evidence.length > 0 && (
              <div className="evidence-box">
                <strong style={{ color: '#fcd34d' }}>Contradicting / Scoping Evidence:</strong>
                <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                  {hyp.contradicting_evidence.map((ev, idx) => (
                    <li key={`${ev.event_id}-c-${idx}`} style={{ marginBottom: 4 }}>
                      <span className="mono">[{ev.event_id}]</span> {ev.summary}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ))}

        <h3 className="card-title" style={{ marginTop: 20 }}>
          Related Metric Deviations
        </h3>
        <div style={{ overflowX: 'auto', marginBottom: 20 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Metric</th>
                <th>Peak Value</th>
                <th>Mode</th>
                <th>Baseline / Threshold</th>
                <th>Consecutive</th>
              </tr>
            </thead>
            <tbody>
              {activeIncident.related_metric_deviations.map((dev, idx) => (
                <tr key={`${dev.service_id}-${dev.metric_name}-${idx}`}>
                  <td>{dev.service_label}</td>
                  <td className="mono">{dev.metric_name}</td>
                  <td className="mono">
                    {dev.peak_value} {dev.unit}
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        dev.detection_mode === 'baseline-based' ? 'badge-baseline' : 'badge-threshold'
                      }`}
                    >
                      {dev.detection_mode}
                    </span>
                  </td>
                  <td className="mono">
                    {dev.baseline_mean !== null
                      ? `mean ${dev.baseline_mean} / thr ${dev.threshold_used}`
                      : `static thr ${dev.threshold_used}`}
                  </td>
                  <td className="mono">{dev.consecutive_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <h3 className="card-title">Incident Timeline</h3>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Event ID</th>
                <th>Service</th>
                <th>Severity</th>
                <th>Observation</th>
              </tr>
            </thead>
            <tbody>
              {activeIncident.timeline.map((step, idx) => (
                <tr key={`${step.event_id}-${idx}`}>
                  <td className="mono">{step.timestamp_utc}</td>
                  <td className="mono">{step.event_id}</td>
                  <td>{step.service_label}</td>
                  <td>
                    <span className={`badge badge-${step.severity}`}>{step.severity}</span>
                  </td>
                  <td>{step.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
