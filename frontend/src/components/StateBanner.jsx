import React from 'react';

export function LoadingState({ message = 'Loading approved telemetry and incident analysis...' }) {
  return (
    <div className="state-panel" role="status" data-testid="loading-state">
      <p style={{ fontSize: 16, fontWeight: 600, color: '#f1f5f9', margin: '0 0 6px 0' }}>
        {message}
      </p>
      <p style={{ margin: 0, fontSize: 13 }}>
        Evaluating deterministic baselines, dependency graph, and SHA-256 egress records.
      </p>
    </div>
  );
}

export function ErrorState({ error, onRetry, onSwitchToMock, stale = false }) {
  return (
    <div
      className="state-panel"
      role="alert"
      data-testid="error-state"
      style={{ borderColor: 'rgba(239, 68, 68, 0.5)' }}
    >
      <p style={{ fontSize: 16, fontWeight: 700, color: '#fca5a5', margin: '0 0 8px 0' }}>
        {stale ? 'Live refresh failed. The data below is STALE (last successful load).' : 'Unable to load telemetry data'}
      </p>
      <p className="mono" style={{ margin: '0 0 16px 0', fontSize: 13 }}>
        {error}
      </p>
      <div style={{ display: 'flex', justifyContent: 'center', gap: 10 }}>
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          Retry Request
        </button>
        {onSwitchToMock && (
          <button type="button" className="btn" onClick={onSwitchToMock}>
            Switch to Mock/Demo mode (simulated data)
          </button>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ title = 'No records available', detail = 'No matching telemetry or incidents were returned for this view.' }) {
  return (
    <div className="state-panel" data-testid="empty-state">
      <p style={{ fontSize: 15, fontWeight: 600, color: '#f1f5f9', margin: '0 0 6px 0' }}>
        {title}
      </p>
      <p style={{ margin: 0, fontSize: 13 }}>{detail}</p>
    </div>
  );
}
