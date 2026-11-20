import React, { useState } from 'react';
import { EmptyState } from './StateBanner';

const short = (h) => (h ? `${h.slice(0, 12)}…${h.slice(-6)}` : null);

function HashCell({ value, testId }) {
  if (!value) {
    return (
      <td className="mono" style={{ color: '#94a3b8' }} data-testid={testId}>
        n/a (mock fixture)
      </td>
    );
  }
  return (
    <td className="mono" title={value} data-testid={testId}>
      {short(value)}
    </td>
  );
}

/**
 * Egress evidence. In Live mode every field comes from the backend: the exact bytes it received,
 * the sender's X-Content-SHA256, the backend's own SHA-256 over those bytes, and its acknowledgement.
 * Nothing is hashed in the browser. Mock fixtures have no backend and are labelled as such.
 */
export default function PrivacyEgressSection({ egressAudit, egressSummary, isLive = false }) {
  const [expandedId, setExpandedId] = useState(null);
  const [typeFilter, setTypeFilter] = useState('all');

  if (!egressAudit || egressAudit.length === 0) {
    return (
      <EmptyState
        title="No egress records"
        detail="No transmissions have been received by the backend for this tenant yet."
      />
    );
  }

  const filtered =
    typeFilter === 'all'
      ? egressAudit
      : egressAudit.filter((rec) => rec.event_type === typeFilter);

  return (
    <section aria-label="Privacy and Egress Audit" className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
        <div>
          <h2 className="card-title" style={{ margin: 0 }}>
            Privacy &amp; Egress Verification Log
          </h2>
          <p style={{ margin: '4px 0 0 0', fontSize: 12.5, color: '#94a3b8' }}>
            {isLive
              ? 'Backend-verified: the SHA-256 shown is calculated by the backend over the exact request body it received, and compared with the hash the collector sent.'
              : 'Mock fixture: simulated records with no backend. Switch to Live API mode for real transfer evidence.'}
          </p>
        </div>

        <select
          aria-label="Filter by Event Type"
          className="control-select"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="all">All Records ({egressAudit.length})</option>
          <option value="metric">metric</option>
          <option value="heartbeat">heartbeat</option>
          <option value="auth_failure_summary">auth_failure_summary</option>
          <option value="rejected">rejected attempts</option>
        </select>
      </div>

      {egressSummary && (
        <div data-testid="egress-summary" style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginBottom: 12, fontSize: 13 }}>
          <span><span className="badge badge-verified">verified</span> {egressSummary.verified}</span>
          <span><span className="badge badge-failed">rejected / failed</span> {egressSummary.rejected}</span>
          <span><span className="badge badge-pending">pending</span> {egressSummary.pending_in_collector_outbox} in collector outbox (as of last heartbeat)</span>
          <span className="mono" style={{ color: '#94a3b8' }}>duplicate deliveries ignored: {egressSummary.duplicate_deliveries}</span>
        </div>
      )}

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Event ID</th>
              <th>Type</th>
              <th>Policy</th>
              <th>Sender SHA-256</th>
              <th>Backend SHA-256</th>
              <th>Hashes match</th>
              <th>Backend result</th>
              <th>Acknowledgement</th>
              <th>Payload</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 40).map((rec) => {
              const isOpen = expandedId === rec.event_id;
              const ack = rec.acknowledgement;
              return (
                <React.Fragment key={rec.event_id}>
                  <tr data-testid={`egress-row-${rec.event_id}`}>
                    <td className="mono">{rec.event_id}</td>
                    <td className="mono">{rec.event_type}</td>
                    <td className="mono">{rec.policy_version}</td>
                    <HashCell value={rec.sender_sha256} testId={`sender-hash-${rec.event_id}`} />
                    <HashCell value={rec.backend_sha256} testId={`backend-hash-${rec.event_id}`} />
                    <td data-testid={`hash-match-${rec.event_id}`}>
                      {rec.hash_match === undefined ? '—' : rec.hash_match ? 'yes' : 'NO'}
                    </td>
                    <td>
                      <span className={`badge badge-${rec.verification_status}`}>
                        {rec.verification_status}
                      </span>
                    </td>
                    <td className="mono" data-testid={`ack-${rec.event_id}`}>
                      {ack ? `${ack.status} (HTTP ${ack.http_status})` : '—'}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => setExpandedId(isOpen ? null : rec.event_id)}
                      >
                        {isOpen ? 'Hide Payload' : 'Inspect Payload'}
                      </button>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr>
                      <td colSpan={9}>
                        <p style={{ margin: '0 0 6px 0', fontSize: 12, color: '#94a3b8' }}>
                          {rec.sent_payload_exact
                            ? 'Exact bytes received by the backend:'
                            : 'Payload (summary only; rejected bodies are never stored):'}
                        </p>
                        <pre className="payload-pre" data-testid={`payload-${rec.event_id}`}>
                          {rec.sent_payload_exact ?? JSON.stringify(rec.approved_payload, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
