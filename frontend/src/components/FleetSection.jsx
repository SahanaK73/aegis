import React from 'react';
import { EmptyState } from './StateBanner';

export default function FleetSection({ fleet }) {
  if (!fleet || fleet.length === 0) {
    return (
      <EmptyState
        title="No collectors registered"
        detail="No collector fleet heartbeat records were returned from the API."
      />
    );
  }

  return (
    <section aria-label="Collector Fleet" className="card">
      <h2 className="card-title">Collector Fleet Health</h2>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Collector ID</th>
              <th>Tenant</th>
              <th>Region</th>
              <th>Service</th>
              <th>Health State</th>
              <th>Last Heartbeat</th>
              <th>Last Telemetry</th>
              <th>Queue Backlog</th>
            </tr>
          </thead>
          <tbody>
            {fleet.map((col) => (
              <tr key={col.collector_id}>
                <td className="mono">{col.collector_id}</td>
                <td>{col.tenant}</td>
                <td className="mono">{col.region}</td>
                <td>{col.service_id}</td>
                <td>
                  <span className={`badge badge-${col.health_state}`}>{col.health_state}</span>
                </td>
                <td className="mono">{col.last_heartbeat || '—'}</td>
                <td className="mono">{col.last_telemetry || '—'}</td>
                <td className="mono">{col.queue_backlog}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
