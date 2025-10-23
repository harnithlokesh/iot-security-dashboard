import React from 'react';

function Settings() {
  return (
    <div className="page-container">
      <h1>Settings</h1>
      <p>Configure your IoT monitoring system here.</p>
      <div className="device-card">
        <div className="device-info">
          <h2>Alert Notifications</h2>
          <p>Enable or disable email/SMS alerts for rogue devices.</p>
        </div>
        <div className="device-actions">
          <button className="quarantine-btn">Toggle</button>
        </div>
      </div>
    </div>
  );
}

export default Settings;
