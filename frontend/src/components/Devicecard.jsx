import React from 'react';
import './DeviceCard.css';

function DeviceCard({ device }) {
  const { name, ip, mac, vendor, status } = device;

  const getStatusClass = () => {
    switch (status) {
      case 'trusted': return 'status trusted';
      case 'rogue': return 'status rogue';
      case 'quarantined': return 'status quarantined';
      default: return 'status';
    }
  };

  return (
    <div className="device-card">
      <div className="device-info">
        <h2>{name}</h2>
        <p>IP: {ip}</p>
        <p>MAC: {mac}</p>
        <p>Vendor: {vendor}</p>
      </div>
      <div className="device-actions">
        <span className={getStatusClass()}>{status.toUpperCase()}</span>
        {status === 'rogue' && <button className="quarantine-btn">Quarantine</button>}
      </div>
    </div>
  );
}

export default DeviceCard;
