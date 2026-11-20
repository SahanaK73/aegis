import React from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { EmptyState } from './StateBanner';

const METRIC_PANELS = [
  { key: 'cpu_percent', title: 'CPU Usage (%)', unit: '%', warn: 80, crit: 92, color: '#38bdf8' },
  { key: 'memory_percent', title: 'Memory Usage (%)', unit: '%', warn: 82, crit: 94, color: '#a855f7' },
  { key: 'latency_ms', title: 'Service Latency (ms)', unit: 'ms', warn: 250, crit: 500, color: '#f59e0b' },
  {
    key: 'packet_loss_percent',
    title: 'Packet Loss (%)',
    unit: '%',
    warn: 2.0,
    crit: 5.0,
    color: '#ef4444',
  },
];

function buildSeries(events, metricName) {
  const byTime = new Map();
  const services = new Set();

  for (const ev of events) {
    if (ev.event_type !== 'metric' || ev.metric_name !== metricName) continue;
    const label = ev.timestamp_utc.slice(11, 19);
    services.add(ev.service_id);
    if (!byTime.has(label)) {
      byTime.set(label, { time: label });
    }
    byTime.get(label)[ev.service_id] = ev.metric_value;
  }

  return {
    data: Array.from(byTime.values()),
    services: Array.from(services),
  };
}

const SERVICE_COLORS = {
  database: '#ef4444',
  'payment-service': '#f59e0b',
  'api-gateway': '#38bdf8',
  'network-service': '#22c55e',
};

const STATE_COLORS = { excellent: '#22c55e', good: '#38bdf8', fair: '#f59e0b', poor: '#ef4444' };

function HealthStrip({ infrastructure }) {
  if (!infrastructure || infrastructure.length === 0) return null;
  return (
    <div className="card" aria-label="Infrastructure health by service" style={{ marginBottom: 16 }}>
      <h2 className="card-title">Service health (from backend)</h2>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {infrastructure.map((s) => (
          <div key={s.service_id} data-testid={`infra-health-${s.service_id}`} title={(s.reasons || []).join('; ')}
            style={{ border: `1px solid ${STATE_COLORS[s.state] || '#64748b'}`, borderRadius: 8, padding: '6px 12px' }}>
            <span className="mono">{s.service_id}</span>{' '}
            <strong style={{ color: STATE_COLORS[s.state] || '#94a3b8' }}>{String(s.state).toUpperCase()}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function InfrastructureSection({ events, infrastructure = [], isLive = false }) {
  const metricEvents = events.filter((e) => e.event_type === 'metric');
  if (metricEvents.length === 0) {
    return (
      <EmptyState
        title="No infrastructure metrics available"
        detail="No approved metric events were returned for CPU, memory, latency, or packet loss."
      />
    );
  }

  return (
    <section aria-label="Infrastructure Metrics">
      {isLive && <HealthStrip infrastructure={infrastructure} />}
      <div className="charts-grid">
        {METRIC_PANELS.map((panel) => {
          const { data, services } = buildSeries(metricEvents, panel.key);
          return (
            <div className="card" key={panel.key}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <h2 className="card-title" style={{ margin: 0 }}>
                  {panel.title}
                </h2>
                <span className="mono" style={{ fontSize: 12, color: '#94a3b8' }}>
                  Warn {panel.warn}{panel.unit} / Crit {panel.crit}{panel.unit}
                </span>
              </div>

              {data.length === 0 ? (
                <p style={{ color: '#64748b', fontSize: 13 }}>
                  No samples recorded for {panel.key} in this window.
                </p>
              ) : (
                <div style={{ width: '100%', height: 240 }}>
                  <ResponsiveContainer>
                    <LineChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                      <YAxis stroke="#94a3b8" fontSize={11} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          color: '#f8fafc',
                          fontSize: 12,
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <ReferenceLine y={panel.warn} stroke="#f59e0b" strokeDasharray="4 4" />
                      <ReferenceLine y={panel.crit} stroke="#ef4444" strokeDasharray="4 4" />
                      {services.map((svc) => (
                        <Line
                          key={svc}
                          type="monotone"
                          dataKey={svc}
                          stroke={SERVICE_COLORS[svc] || panel.color}
                          strokeWidth={2}
                          dot={{ r: 3 }}
                          activeDot={{ r: 5 }}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
