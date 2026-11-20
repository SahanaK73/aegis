import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import App from '../App';

describe('Aegis Observability Dashboard', () => {
  it('renders clearly labeled Mock Mode banner and Overview KPIs', async () => {
    render(<App initialUseMock={true} />);

    expect(await screen.findByTestId('mock-mode-banner')).toHaveTextContent(/MOCK MODE ACTIVE/i);
    expect(screen.getByTestId('data-mode-badge')).toHaveTextContent(/Mock Fixture Mode/i);
    expect(screen.getByTestId('kpi-active-incidents')).toHaveTextContent('1');
    expect(screen.getByTestId('kpi-healthy-collectors')).toHaveTextContent('3');
    expect(screen.getByTestId('kpi-unhealthy-collectors')).toHaveTextContent('1');
  });

  it('displays correlated incidents with ranked hypotheses and supporting evidence', async () => {
    render(<App initialUseMock={true} />);
    await screen.findByTestId('kpi-active-incidents');

    fireEvent.click(screen.getByText('D. Incidents & RCA'));
    expect(screen.getByText(/Ranked Root-Cause Hypotheses/i)).toBeInTheDocument();
    expect(screen.getByText(/#1 Hypothesis:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Supporting Evidence:/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/API Gateway -> Payment Service -> Database/i)).toBeInTheDocument();
  });

  it('displays Fleet health and Privacy/Egress SHA-256 verification records', async () => {
    render(<App initialUseMock={true} />);
    await screen.findByTestId('kpi-active-incidents');

    fireEvent.click(screen.getByText('C. Fleet'));
    expect(screen.getByText('col-db-01')).toBeInTheDocument();
    expect(screen.getAllByText('acme-payments').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('E. Privacy / Egress'));
    expect(screen.getByText(/Privacy & Egress Verification Log/i)).toBeInTheDocument();
    expect(screen.getAllByText('verified').length).toBeGreaterThan(0);
  });

  it('supports human approval simulation and records an audit entry', async () => {
    render(<App initialUseMock={true} />);
    await screen.findByTestId('kpi-active-incidents');

    fireEvent.click(screen.getByText('F. Remediation'));
    expect(screen.getByTestId('approval-status-INC-0001')).toHaveTextContent(
      /pending human approval/i
    );

    fireEvent.click(screen.getByText('Simulate Human Approval'));
    await waitFor(() => {
      expect(screen.getByTestId('approval-status-INC-0001')).toHaveTextContent(/approved/i);
    });
    expect(screen.getByText(/sre-operator@aegis/i)).toBeInTheDocument();
  });
});
