import React from 'react';
import './Dashboard.css';

function Dashboard() {
  const stats = {
    totalDevices: 12,
    trustedDevices: 8,
    rogueDevices: 2,
    quarantinedDevices: 2,
    alertsLast24h: 5,
  };

  return (
    <div className="dashboard-page">
      <h1>Network Overview</h1>
      <div className="stats-grid">
        {Object.entries(stats).map(([key, value]) => (
          <div className={`stat-card ${key}`} key={key}>
            <h2>{value}</h2>
            <p>{key.replace(/([A-Z])/g, ' $1')}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Dashboard;
