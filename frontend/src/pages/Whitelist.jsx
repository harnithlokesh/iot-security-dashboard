import React from 'react';

function Whitelist() {
  return (
    <div className="page-container">
      <h1>Whitelist Devices</h1>
      <p>Here you can see all trusted IoT devices added to the whitelist.</p>
      {/* Example table or card grid */}
      <div className="stats-grid">
        <div className="stat-card trustedDevices">
          <h2>3</h2>
          <p>Trusted Devices</p>
        </div>
      </div>
    </div>
  );
}

export default Whitelist;
