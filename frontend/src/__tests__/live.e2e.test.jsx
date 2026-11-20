// Runs against a REAL running backend. Used by scripts/run_e2e.py (npm run test:live).
// Requires AEGIS_LIVE_API_URL; fails loudly (not skipped) if it is missing.
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import App from '../App';
import { fetchDashboardData } from '../services/apiClient';

const URL_ = process.env.AEGIS_LIVE_API_URL;
const TOKEN = process.env.AEGIS_LIVE_API_TOKEN || 'dev-token-tenant-a';

describe('Dashboard against the real backend', () => {
  it('has a backend URL', () => {
    expect(URL_, 'set AEGIS_LIVE_API_URL').toBeTruthy();
  });

  it('client fetches real incident, anomalies and backend-verified egress', async () => {
    const d = await fetchDashboardData({ useMock: false, apiBaseUrl: URL_, apiToken: TOKEN });
    expect(d.sourceMode).toBe('live');
    expect(d.incidents.length).toBeGreaterThan(0);
    const inc = d.incidents[0];
    expect(inc.root_cause_hypotheses[0].rank).toBe(1);
    expect(inc.root_cause_hypotheses[0].supporting_evidence.length).toBeGreaterThan(0);
    const verified = d.egressAudit.filter((r) => r.verification_status === 'verified');
    expect(verified.length).toBeGreaterThan(0);
    for (const r of verified) {
      expect(r.sender_sha256).toBe(r.backend_sha256);
      expect(r.hash_match).toBe(true);
    }
  });

  it('a wrong token is rejected and shown as an error', async () => {
    await expect(fetchDashboardData({ useMock: false, apiBaseUrl: URL_, apiToken: 'wrong' })).rejects.toThrow(/HTTP 401/);
  });

  it('React dashboard displays the real incident, evidence and backend egress proof', async () => {
    render(<App initialUseMock={false} initialApiBaseUrl={URL_} initialApiToken={TOKEN} refreshMs={0} />);
    expect(await screen.findByTestId('kpi-active-incidents', {}, { timeout: 8000 })).not.toHaveTextContent(/^0$/);
    expect(screen.getByTestId('data-mode-badge')).toHaveTextContent(/Live API Mode/i);
    fireEvent.click(screen.getByText('D. Incidents & RCA'));
    expect(screen.getByText(/Ranked Root-Cause Hypotheses/i)).toBeInTheDocument();
    expect(screen.getByText(/#1 Hypothesis:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Supporting Evidence:/i).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText('E. Privacy / Egress'));
    expect(screen.getByTestId('egress-summary')).toBeInTheDocument();
    expect(screen.getAllByText('verified').length).toBeGreaterThan(0);
  });
});
