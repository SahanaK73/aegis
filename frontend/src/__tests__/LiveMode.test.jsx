import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import App from '../App';
import { fetchDashboardData } from '../services/apiClient';

const env = (data) => ({ status: 'ok', generated_at: '2026-11-20T10:00:00Z', tenant_id: 'tenant-a', data });
const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });

const HEALTH = env({ status: 'degraded', engine: 'aegis-aiops-deterministic', graph_engine: 'networkx',
  active_incidents: 1, healthy_collectors: 1, unhealthy_collectors: 0, anomaly_count: 4 });
const EVENT = { event_id: 'evt-000001', collector_id: 'collector-001', event_type: 'metric',
  service_id: 'payment-service', timestamp_utc: '2026-11-20T10:00:00Z', source_timezone: 'Asia/Kolkata',
  region: 'ap-south', severity: 'critical', policy_version: 'v1', metric_name: 'latency_ms',
  metric_value: 640, unit: 'ms' };
const RAW = JSON.stringify(EVENT);
const RECENT = env({ events: [EVENT], egress_audit: [{
  event_id: 'evt-000001', event_type: 'metric', service_id: 'payment-service', collector_id: 'collector-001',
  timestamp_utc: EVENT.timestamp_utc, policy_version: 'v1', approved_payload: EVENT, sent_payload_exact: RAW,
  sender_sha256: 'a'.repeat(64), backend_sha256: 'a'.repeat(64), sha256_hash: 'a'.repeat(64), hash_match: true,
  verification_status: 'verified', acknowledgement: { status: 'accepted', http_status: 200 } },
  { event_id: 'attempt-1', event_type: 'rejected', service_id: 'n/a', collector_id: 'n/a', timestamp_utc: 'x',
  policy_version: 'n/a', approved_payload: {}, sent_payload_exact: null, sender_sha256: '0'.repeat(64),
  backend_sha256: 'b'.repeat(64), sha256_hash: 'b'.repeat(64), hash_match: false,
  verification_status: 'hash_mismatch', acknowledgement: { status: 'rejected', http_status: 400 } }],
  egress_summary: { verified: 1, rejected: 1, duplicate_deliveries: 0, pending_in_collector_outbox: 2 } });
const FLEET = env({ collectors: [{ collector_id: 'collector-001', tenant_id: 'tenant-a', tenant_name: 'Tenant A',
  region: 'ap-south', collector_version: '0.1.0', last_heartbeat_at: 'h', last_telemetry_at: 't', queue_backlog: 0,
  collector_health: { state: 'excellent', reasons: ['ok'] } }], infrastructure: [] });
const INCIDENT = { incident_id: 'INC-0001', title: 'Correlated Payment Path Degradation', severity: 'critical',
  status: 'active', first_observed_utc: '2026-11-20T10:00:00Z', affected_services: [{ service_id: 'payment-service', label: 'Payment Service' }],
  related_metric_deviations: [], dependency_path: ['API Gateway -> Payment Service -> Database'], timeline: [],
  supporting_evidence: [], contradicting_evidence: [], confidence_explanation: 'x',
  root_cause_hypotheses: [{ rank: 1, service_id: 'payment-service', service_label: 'Payment Service',
    hypothesis: 'Sustained latency on Payment Service', is_hypothesis: true, confidence_score: 0.82,
    confidence_label: 'High-priority hypothesis (not confirmed)', ranking_explanation: 'r',
    supporting_evidence: [{ description: 's' }], contradicting_evidence: [] }],
  recommended_action: { action: 'a', approval_required: true, approval_status: 'pending_human_approval', rollback_note: 'n', audit_records: [] } };
const INCIDENTS = env({ incidents: [INCIDENT], anomalies: [], dependency_graph: { nodes: [], edges: [] } });
const EMPTY_INCIDENTS = env({ incidents: [], anomalies: [], dependency_graph: { nodes: [], edges: [] } });
const EMPTY_RECENT = env({ events: [], egress_audit: [], egress_summary: { verified: 0, rejected: 0, duplicate_deliveries: 0, pending_in_collector_outbox: 0 } });

function router(overrides = {}) {
  const routes = { '/api/v1/health': HEALTH, '/api/v1/events/recent': RECENT, '/api/v1/fleet': FLEET,
    '/api/v1/incidents': INCIDENTS, ...overrides };
  return vi.fn(async (url) => {
    const path = new URL(url).pathname;
    const r = routes[path];
    return typeof r === 'function' ? r() : json(r);
  });
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('Live API mode', () => {
  it('sends the Bearer token on every request and unwraps the {data} envelope', async () => {
    const f = router();
    vi.stubGlobal('fetch', f);
    const d = await fetchDashboardData({ useMock: false, apiBaseUrl: 'http://x:8000', apiToken: 'tok-1' });
    expect(f).toHaveBeenCalledTimes(4);
    for (const [, opts] of f.mock.calls) expect(opts.headers.Authorization).toBe('Bearer tok-1');
    expect(d.sourceMode).toBe('live');
    expect(d.incidents[0].incident_id).toBe('INC-0001');
    expect(d.fleet[0].health_state).toBe('excellent');
    expect(d.fleet[0].tenant).toBe('Tenant A');
    expect(d.health.active_incidents).toBe(1);
  });

  it('renders live incident, fleet and backend egress evidence (no mock banner)', async () => {
    vi.stubGlobal('fetch', router());
    render(<App initialUseMock={false} refreshMs={0} />);
    expect(await screen.findByTestId('kpi-active-incidents')).toHaveTextContent('1');
    expect(screen.getByTestId('data-mode-badge')).toHaveTextContent(/Live API Mode/i);
    expect(screen.queryByTestId('mock-mode-banner')).toBeNull();

    fireEvent.click(screen.getByText('D. Incidents & RCA'));
    expect(screen.getAllByText(/Correlated Payment Path Degradation/).length).toBeGreaterThan(0);
    expect(screen.getByText(/#1 Hypothesis:/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText('E. Privacy / Egress'));
    expect(screen.getByTestId('egress-summary')).toHaveTextContent('2 in collector outbox');
    expect(screen.getByTestId('hash-match-evt-000001')).toHaveTextContent('yes');
    expect(screen.getByTestId('ack-evt-000001')).toHaveTextContent('accepted (HTTP 200)');
    expect(screen.getByTestId('hash-match-attempt-1')).toHaveTextContent('NO');
    expect(screen.getAllByText('hash_mismatch').length).toBeGreaterThan(0);
    fireEvent.click(screen.getAllByText('Inspect Payload')[0]);
    expect(screen.getByTestId('payload-evt-000001')).toHaveTextContent('"metric_name":"latency_ms"');
  });

  it('shows an API error and never substitutes mock data', async () => {
    vi.stubGlobal('fetch', router({ '/api/v1/fleet': () => json({ status: 'rejected', code: 'unauthorized' }, 401) }));
    render(<App initialUseMock={false} refreshMs={0} />);
    const err = await screen.findByTestId('error-state');
    expect(err).toHaveTextContent(/HTTP 401/);
    expect(screen.queryByTestId('kpi-active-incidents')).toBeNull();
    expect(screen.queryByTestId('mock-mode-banner')).toBeNull();
  });

  it('shows a network failure as an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    render(<App initialUseMock={false} refreshMs={0} />);
    expect(await screen.findByTestId('error-state')).toHaveTextContent(/Cannot reach backend/);
  });

  it('handles empty API responses with empty states', async () => {
    vi.stubGlobal('fetch', router({
      '/api/v1/events/recent': EMPTY_RECENT, '/api/v1/incidents': EMPTY_INCIDENTS,
      '/api/v1/fleet': env({ collectors: [], infrastructure: [] }),
      '/api/v1/health': env({ status: 'healthy', active_incidents: 0, healthy_collectors: 0, unhealthy_collectors: 0, anomaly_count: 0 }),
    }));
    render(<App initialUseMock={false} refreshMs={0} />);
    expect(await screen.findByTestId('kpi-active-incidents')).toHaveTextContent('0');
    fireEvent.click(screen.getByText('D. Incidents & RCA'));
    expect(screen.getByText(/No active incidents/i)).toBeInTheDocument();
    fireEvent.click(screen.getByText('C. Fleet'));
    expect(screen.getByText(/No collectors registered/i)).toBeInTheDocument();
    fireEvent.click(screen.getByText('E. Privacy / Egress'));
    expect(screen.getByText(/No egress records/i)).toBeInTheDocument();
  });

  it('periodic refresh replaces data (no duplicate incidents) and keeps stale data labelled on failure', async () => {
    let fail = false;
    const f = vi.fn(async (url) => {
      if (fail) throw new TypeError('Failed to fetch');
      const path = new URL(url).pathname;
      return json({ '/api/v1/health': HEALTH, '/api/v1/events/recent': RECENT, '/api/v1/fleet': FLEET, '/api/v1/incidents': INCIDENTS }[path]);
    });
    vi.stubGlobal('fetch', f);
    render(<App initialUseMock={false} refreshMs={40} />);
    await screen.findByTestId('kpi-active-incidents');
    fireEvent.click(screen.getByText('D. Incidents & RCA'));
    await waitFor(() => expect(f.mock.calls.length).toBeGreaterThanOrEqual(12)); // several refresh cycles
    expect(screen.getByText(/Correlated Incidents \(1\)/)).toBeInTheDocument(); // still exactly one
    fail = true;
    const err = await screen.findByTestId('error-state');
    expect(err).toHaveTextContent(/STALE/);
    expect(screen.queryByTestId('mock-mode-banner')).toBeNull();
  });

  it('mock mode is still explicit and labelled', async () => {
    render(<App initialUseMock={true} />);
    expect(await screen.findByTestId('mock-mode-banner')).toHaveTextContent(/MOCK MODE ACTIVE/i);
  });
});

describe('Infrastructure health (regression: /fleet infrastructure was fetched but never shown)', () => {
  const INFRA = [{ service_id: 'payment-service', state: 'poor', reasons: ['latency_ms=640ms severity critical'], latest: [] },
    { service_id: 'database', state: 'excellent', reasons: [], latest: [] }];
  const fleetWith = env({ ...FLEET.data, infrastructure: INFRA });

  it('shows the backend per-service health state in live mode', async () => {
    vi.stubGlobal('fetch', router({ '/api/v1/fleet': fleetWith }));
    render(<App initialUseMock={false} refreshMs={0} />);
    await screen.findByTestId('kpi-active-incidents');
    fireEvent.click(screen.getByText('B. Infrastructure'));
    expect(screen.getByTestId('infra-health-payment-service')).toHaveTextContent('POOR');
    expect(screen.getByTestId('infra-health-database')).toHaveTextContent('EXCELLENT');
  });
});
