import React, { useState } from 'react';
import { EmptyState } from './StateBanner';

export default function RemediationSection({
  incidents,
  remediationState,
  onRecordDecision,
}) {
  const [operatorNotes, setOperatorNotes] = useState({});

  if (!incidents || incidents.length === 0) {
    return (
      <EmptyState
        title="No pending remediations"
        detail="Human-approved remediation actions appear here when active incidents are detected."
      />
    );
  }

  return (
    <section aria-label="Remediation and Human Approval">
      {incidents.map((inc) => {
        const rec = inc.recommended_action;
        const override = remediationState[inc.incident_id];
        const status = override?.approval_status || rec.approval_status;
        const auditRecords = override?.audit_records || rec.audit_records || [];
        const noteValue = operatorNotes[inc.incident_id] || '';

        const submitDecision = (decision) => {
          onRecordDecision(inc.incident_id, {
            decision,
            note:
              noteValue.trim() ||
              (decision === 'approved'
                ? 'Operator verified supporting evidence and approved mitigation.'
                : 'Operator rejected proposed remediation pending further investigation.'),
          });
          setOperatorNotes((prev) => ({ ...prev, [inc.incident_id]: '' }));
        };

        return (
          <div className="card" key={inc.incident_id} style={{ marginBottom: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <span className="mono" style={{ fontSize: 12, color: '#94a3b8' }}>
                  {inc.incident_id} · {inc.title}
                </span>
                <h2 className="card-title" style={{ marginTop: 4 }}>
                  Recommended Human-Approved Action
                </h2>
              </div>
              <span
                className={`badge badge-${status}`}
                data-testid={`approval-status-${inc.incident_id}`}
              >
                {status.replace(/_/g, ' ')}
              </span>
            </div>

            <p style={{ margin: '0 0 12px 0', fontSize: 14 }}>{rec.action}</p>

            <div className="evidence-box" style={{ marginBottom: 14 }}>
              <strong style={{ color: '#7dd3fc' }}>Rollback Note:</strong> {rec.rollback_note}
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginBottom: 16 }}>
              <input
                type="text"
                aria-label={`Operator approval note for ${inc.incident_id}`}
                className="control-input"
                style={{ flex: '1 1 280px' }}
                placeholder="Optional operator justification for audit log..."
                value={noteValue}
                onChange={(e) =>
                  setOperatorNotes((prev) => ({ ...prev, [inc.incident_id]: e.target.value }))
                }
              />
              <button
                type="button"
                className="btn btn-approve"
                onClick={() => submitDecision('approved')}
              >
                Simulate Human Approval
              </button>
              <button
                type="button"
                className="btn btn-reject"
                onClick={() => submitDecision('rejected')}
              >
                Reject Action
              </button>
            </div>

            <h3 className="card-title" style={{ fontSize: 13 }}>
              Audit Record
            </h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Actor</th>
                  <th>Decision</th>
                  <th>Audit Note</th>
                </tr>
              </thead>
              <tbody>
                {auditRecords.map((entry, idx) => (
                  <tr key={`${inc.incident_id}-aud-${idx}`}>
                    <td className="mono">{entry.timestamp_utc}</td>
                    <td className="mono">{entry.actor}</td>
                    <td>
                      <span className={`badge badge-${entry.decision === 'proposed' ? 'warning' : entry.decision}`}>
                        {entry.decision}
                      </span>
                    </td>
                    <td>{entry.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </section>
  );
}
