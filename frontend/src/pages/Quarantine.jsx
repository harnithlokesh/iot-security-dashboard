import React from 'react';

function Quarantine() {
  return (
    <div className="page-container">
      <h1>Quarantined Devices</h1>
      <p>Devices that were detected as unauthorized and quarantined will appear here.</p>
      {/* Example device cards */}
      <div className="device-card">
        <div className="device-info">
          <h2>Device 1</h2>
          <p>MAC: 00:11:22:33:44:55</p>
          <p>Status: Quarantined</p>
        </div>
        <div className="device-actions">
          <button className="quarantine-btn">Release</button>
        </div>
      </div>
    </div>
  );
}

export default Quarantine;
