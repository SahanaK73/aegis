import React from 'react';
import { SCENARIO_OPTIONS } from '../services/apiClient';

export default function HeaderBar({
  useMock,
  onToggleMock,
  apiBaseUrl,
  onApiBaseUrlChange,
  apiToken,
  onApiTokenChange,
  lastUpdated,
  scenarioKey,
  onScenarioChange,
  scenarioDescription,
  onRefresh,
  loading,
}) {
  return (
    <>
      <header className="header-bar">
        <div className="brand-group">
          <div className="brand-mark" aria-hidden="true">
            A
          </div>
          <div>
            <h1 className="brand-title">Aegis Observability &amp; AIOps</h1>
            <p className="brand-subtitle">
              Privacy-first deterministic anomaly detection &amp; evidence-backed root-cause analysis
            </p>
          </div>
        </div>

        <div className="controls-bar">
          <span className={`mode-pill ${useMock ? 'mock' : 'live'}`} data-testid="data-mode-badge">
            {useMock ? 'Mock Fixture Mode' : 'Live API Mode'}
          </span>

          <button type="button" className="btn" onClick={onToggleMock}>
            Switch to {useMock ? 'Live API' : 'Mock Mode'}
          </button>

          {useMock ? (
            <select
              aria-label="Simulated Telemetry Scenario"
              className="control-select"
              value={scenarioKey}
              onChange={(e) => onScenarioChange(e.target.value)}
            >
              {SCENARIO_OPTIONS.map((opt) => (
                <option key={opt.key} value={opt.key}>
                  Scenario: {opt.label}
                </option>
              ))}
            </select>
          ) : (
            <>
              <input
                type="url"
                aria-label="Backend API Base URL"
                className="control-input"
                value={apiBaseUrl}
                onChange={(e) => onApiBaseUrlChange(e.target.value)}
                placeholder="http://localhost:8000"
                style={{ width: 200 }}
              />
              <input
                type="password"
                aria-label="Tenant API Token (development)"
                className="control-input"
                value={apiToken}
                onChange={(e) => onApiTokenChange(e.target.value)}
                placeholder="tenant bearer token"
                style={{ width: 170 }}
              />
              {lastUpdated && (
                <span className="mono" data-testid="last-updated" style={{ fontSize: 11, color: '#94a3b8' }}>
                  updated {lastUpdated.slice(11, 19)}Z
                </span>
              )}
            </>
          )}

          <button
            type="button"
            className="btn btn-primary"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </header>

      {useMock && (
        <div className="mock-banner" role="status" data-testid="mock-mode-banner">
          <span>
            <strong>MOCK MODE ACTIVE:</strong> Displaying deterministic AIOps output generated from
            simulated telemetry fixtures (not live backend data). {scenarioDescription}
          </span>
          <span className="mono">Schema: shared/event_schema.json</span>
        </div>
      )}
    </>
  );
}
