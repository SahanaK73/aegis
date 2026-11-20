import React, { useCallback, useEffect, useState } from 'react';
import HeaderBar from './components/HeaderBar';
import { ErrorState, LoadingState } from './components/StateBanner';
import OverviewSection from './components/OverviewSection';
import InfrastructureSection from './components/InfrastructureSection';
import FleetSection from './components/FleetSection';
import IncidentsSection from './components/IncidentsSection';
import PrivacyEgressSection from './components/PrivacyEgressSection';
import RemediationSection from './components/RemediationSection';
import {
  DEFAULT_API_BASE_URL,
  DEFAULT_API_TOKEN,
  DEFAULT_USE_MOCK,
  fetchDashboardData,
} from './services/apiClient';

// Live mode re-fetches this often. Data is REPLACED each time (never appended), so incidents,
// events and egress rows cannot duplicate across refreshes.
export const LIVE_REFRESH_MS = Number(import.meta?.env?.VITE_REFRESH_MS || 5000);

const TABS = [
  { id: 'overview', label: 'A. Overview' },
  { id: 'infrastructure', label: 'B. Infrastructure' },
  { id: 'fleet', label: 'C. Fleet' },
  { id: 'incidents', label: 'D. Incidents & RCA' },
  { id: 'privacy', label: 'E. Privacy / Egress' },
  { id: 'remediation', label: 'F. Remediation' },
];

export default function App({
  initialData = null,
  initialUseMock = DEFAULT_USE_MOCK,
  initialApiBaseUrl = DEFAULT_API_BASE_URL,
  initialApiToken = DEFAULT_API_TOKEN,
  refreshMs = LIVE_REFRESH_MS,
}) {
  const [activeTab, setActiveTab] = useState('overview');
  const [useMock, setUseMock] = useState(initialUseMock);
  const [apiBaseUrl, setApiBaseUrl] = useState(initialApiBaseUrl);
  const [apiToken, setApiToken] = useState(initialApiToken);
  const [scenarioKey, setScenarioKey] = useState('correlated_anomalies');
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(!initialData);
  const [error, setError] = useState(null);
  const [remediationState, setRemediationState] = useState({});

  // `silent` refreshes (the periodic poll) keep the current view on screen; a failure is shown as an
  // error banner and the stale data is labelled as such. Mock data is never substituted.
  const loadData = useCallback(
    async ({ silent = false } = {}) => {
      if (!silent) setLoading(true);
      try {
        const result = await fetchDashboardData({ useMock, apiBaseUrl, apiToken, scenarioKey });
        setData(result);
        setError(null);
      } catch (err) {
        setError(err.message || 'Failed to fetch telemetry data.');
        if (!silent) setData(null);
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [useMock, apiBaseUrl, apiToken, scenarioKey]
  );

  useEffect(() => {
    if (!initialData) {
      loadData();
    }
  }, [loadData, initialData]);

  useEffect(() => {
    if (useMock || !refreshMs || initialData) return undefined;
    const id = setInterval(() => loadData({ silent: true }), refreshMs);
    return () => clearInterval(id);
  }, [useMock, refreshMs, loadData, initialData]);

  const handleRecordDecision = (incidentId, { decision, note }) => {
    const incident = data?.incidents?.find((i) => i.incident_id === incidentId);
    const baseRecords =
      remediationState[incidentId]?.audit_records ||
      incident?.recommended_action?.audit_records ||
      [];

    const newRecord = {
      timestamp_utc: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      actor: 'sre-operator@aegis (simulated)',
      decision,
      note,
    };

    setRemediationState((prev) => ({
      ...prev,
      [incidentId]: {
        approval_status: decision,
        audit_records: [...baseRecords, newRecord],
      },
    }));
  };

  return (
    <div className="app-shell">
      <HeaderBar
        useMock={useMock}
        onToggleMock={() => setUseMock((m) => !m)}
        apiBaseUrl={apiBaseUrl}
        onApiBaseUrlChange={setApiBaseUrl}
        apiToken={apiToken}
        onApiTokenChange={setApiToken}
        lastUpdated={data?.fetchedAt || null}
        scenarioKey={scenarioKey}
        onScenarioChange={(key) => {
          setScenarioKey(key);
          setRemediationState({});
        }}
        scenarioDescription={data?.scenarioDescription || ''}
        onRefresh={() => loadData()}
        loading={loading}
      />

      <nav className="nav-tabs" aria-label="Dashboard Sections">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="main-content">
        {loading && <LoadingState />}
        {!loading && error && (
          <ErrorState
            error={error}
            onRetry={() => loadData()}
            onSwitchToMock={!useMock ? () => setUseMock(true) : null}
            stale={Boolean(data)}
          />
        )}
        {!loading && data && (
          <>
            {activeTab === 'overview' && (
              <OverviewSection
                health={data.health}
                dependencyGraph={data.dependencyGraph}
                anomalies={data.anomalies}
                incidents={data.incidents}
                onOpenIncidents={() => setActiveTab('incidents')}
              />
            )}
            {activeTab === 'infrastructure' && (
              <InfrastructureSection events={data.events} infrastructure={data.infrastructure} isLive={data.sourceMode === 'live'} />
            )}
            {activeTab === 'fleet' && <FleetSection fleet={data.fleet} />}
            {activeTab === 'incidents' && (
              <IncidentsSection
                incidents={data.incidents}
                onGoToRemediation={() => setActiveTab('remediation')}
              />
            )}
            {activeTab === 'privacy' && (
              <PrivacyEgressSection
                egressAudit={data.egressAudit}
                egressSummary={data.egressSummary}
                isLive={data.sourceMode === 'live'}
              />
            )}
            {activeTab === 'remediation' && (
              <RemediationSection
                incidents={data.incidents}
                remediationState={remediationState}
                onRecordDecision={handleRecordDecision}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}
