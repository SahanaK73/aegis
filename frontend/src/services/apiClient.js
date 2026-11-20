import mockBundle from '../fixtures/mockApiData.json';

export const DEFAULT_API_BASE_URL =
  import.meta?.env?.VITE_API_BASE_URL || 'http://localhost:8000';

// Live API is the default. Mock/Demo mode must be chosen explicitly (VITE_USE_MOCK=true or the header toggle).
export const DEFAULT_USE_MOCK =
  (import.meta?.env?.VITE_USE_MOCK ?? 'false').toLowerCase() === 'true';

// DEVELOPMENT-ONLY token for the simulated tenant (see backend/config.py). Never ship a real secret here:
// anything in a VITE_ variable is readable in the browser bundle.
export const DEFAULT_API_TOKEN = import.meta?.env?.VITE_API_TOKEN || 'dev-token-tenant-a';

export const SCENARIO_OPTIONS = Object.entries(mockBundle.scenarios).map(([key, val]) => ({
  key,
  label: val.scenario_label || key,
  description: val.scenario_description || '',
}));


export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** GET a backend endpoint with the tenant Bearer token and unwrap the {status, data} envelope. */
async function fetchEnvelope(url, token) {
  let res;
  try {
    res = await fetch(url, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    });
  } catch (err) {
    throw new ApiError(`Cannot reach backend at ${url} (${err.message}). Is it running, and is CORS allowed?`, 0);
  }
  let body = null;
  try {
    body = await res.json();
  } catch (_) {
    /* non-JSON error body */
  }
  if (!res.ok) {
    const code = body?.code ? ` (${body.code})` : '';
    throw new ApiError(`HTTP ${res.status} from ${url}${code}`, res.status);
  }
  if (!body || typeof body !== 'object' || !('data' in body)) {
    throw new ApiError(`Unexpected response shape from ${url}: missing "data" envelope`, res.status);
  }
  return body.data;
}

/** Map a backend fleet collector onto the shape the Fleet table renders. Four states are kept as-is. */
export function mapCollector(c) {
  return {
    collector_id: c.collector_id,
    tenant: c.tenant_name || c.tenant_id,
    region: c.region,
    service_id: c.service_id || 'collector',
    health_state: c.collector_health?.state || 'poor',
    health_reasons: c.collector_health?.reasons || [],
    last_heartbeat: c.last_heartbeat_at,
    last_telemetry: c.last_telemetry_at,
    queue_backlog: c.queue_backlog ?? 0,
    collector_version: c.collector_version || 'unknown',
    cpu_percent: c.cpu_percent,
    memory_percent: c.memory_percent,
  };
}

/**
 * Fetch unified observability state from either Mock Fixtures or the Live FastAPI backend.
 *
 * Live mode NEVER falls back to mock data: any failure is thrown to the caller and shown as an error.
 * Egress evidence comes only from the backend (its own SHA-256 over the exact received bytes);
 * nothing is hashed in the browser.
 *
 * Live endpoints consumed (all need `Authorization: Bearer <token>`, all return {status, data}):
 *   GET /api/v1/health, /api/v1/events/recent, /api/v1/fleet, /api/v1/incidents
 */
export async function fetchDashboardData({
  useMock = false,
  apiBaseUrl = DEFAULT_API_BASE_URL,
  apiToken = DEFAULT_API_TOKEN,
  scenarioKey = 'correlated_anomalies',
} = {}) {
  if (useMock) {
    const scenario =
      mockBundle.scenarios[scenarioKey] || mockBundle.scenarios.correlated_anomalies;
    return {
      sourceMode: 'mock',
      scenarioKey,
      scenarioLabel: scenario.scenario_label,
      scenarioDescription: scenario.scenario_description,
      health: scenario.health,
      dependencyGraph: scenario.dependency_graph,
      events: scenario.events,
      egressAudit: scenario.egress_audit,
      egressSummary: null,
      fleet: scenario.fleet,
      infrastructure: [],
      anomalies: scenario.anomalies,
      incidents: scenario.incidents,
    };
  }

  const base = apiBaseUrl.replace(/\/+$/, '');
  const [health, recent, fleetData, incidentData] = await Promise.all([
    fetchEnvelope(`${base}/api/v1/health`, apiToken),
    fetchEnvelope(`${base}/api/v1/events/recent?limit=300`, apiToken),
    fetchEnvelope(`${base}/api/v1/fleet`, apiToken),
    fetchEnvelope(`${base}/api/v1/incidents`, apiToken),
  ]);

  const fleet = (fleetData.collectors || []).map(mapCollector);
  const incidents = incidentData.incidents || [];

  return {
    sourceMode: 'live',
    scenarioKey: null,
    scenarioLabel: 'Live API',
    scenarioDescription: `Connected to ${base}`,
    fetchedAt: new Date().toISOString(),
    health: {
      status: health.status || 'unknown',
      engine: health.engine,
      graph_engine: health.graph_engine,
      active_incidents: health.active_incidents ?? incidents.length,
      healthy_collectors: health.healthy_collectors ?? 0,
      unhealthy_collectors: health.unhealthy_collectors ?? 0,
      anomaly_count: health.anomaly_count ?? (incidentData.anomalies || []).length,
      aiops_errors: health.aiops_errors ?? 0,
    },
    dependencyGraph: incidentData.dependency_graph,
    events: recent.events || [],
    egressAudit: recent.egress_audit || [],
    egressSummary: recent.egress_summary || null,
    fleet,
    infrastructure: fleetData.infrastructure || [],
    anomalies: incidentData.anomalies || [],
    incidents,
    analysis: incidentData.analysis || null,
  };
}
