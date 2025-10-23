import React, { useEffect, useState } from 'react';
import { API_URL } from '../config';
import './Scanner.css';

export default function Scanner() {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [quarantineLoading, setQuarantineLoading] = useState({}); // deviceId -> bool

  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API_URL}/devices`);
      const data = await res.json();
      setDevices(data);
    } catch (err) {
      console.error('fetchDevices', err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_URL}/alerts`);
      const data = await res.json();
      setAlerts(data);
    } catch (err) {
      console.error('fetchAlerts', err);
    }
  };

  useEffect(() => {
    let mounted = true;
    const all = async () => {
      await Promise.all([fetchDevices(), fetchAlerts()]);
      if (mounted) setLoading(false);
    };
    all();
    const int = setInterval(() => {
      fetchDevices();
      fetchAlerts();
    }, 3000); // poll every 3s
    return () => {
      mounted = false;
      clearInterval(int);
    };
  }, []);

  const requestApproveQuarantine = async (deviceId) => {
    setQuarantineLoading(prev => ({ ...prev, [deviceId]: true }));
    try {
      // call approve endpoint (admin action)
      const res = await fetch(`${API_URL}/quarantine/approve/${deviceId}`, {
        method: 'POST'
      });
      if (!res.ok) throw new Error('Failed');
      await fetchDevices();
      await fetchAlerts();
    } catch (err) {
      console.error('approveQuarantine', err);
      alert('Failed to approve quarantine');
    } finally {
      setQuarantineLoading(prev => ({ ...prev, [deviceId]: false }));
    }
  };

  const requestManualQuarantine = async (mac) => {
    // optional: allow admin to directly request quarantine from frontend
    try {
      const res = await fetch(`${API_URL}/quarantine/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac })
      });
      if (!res.ok) throw new Error('failed');
      await fetchDevices();
      await fetchAlerts();
    } catch (err) {
      console.error(err);
      alert('Failed to request quarantine');
    }
  };

  return (
    <div className="scanner-page">
      <h1>Network Scanner</h1>
      <div className="scanner-columns">
        <section className="devices-col">
          <h2>Devices</h2>
          {loading ? <p>Loading...</p> : null}
          <div className="device-list">
            {devices.map(d => (
              <div className="device-card" key={d._id}>
                <div>
                  <strong>{d.name}</strong>
                  <div className="muted">{d.mac} • {d.ip || '—'}</div>
                  <div className="muted">Status: <span className={`status ${d.status}`}>{d.status}</span></div>
                  {d.pendingQuarantine ? <div className="muted">Pending quarantine</div> : null}
                </div>
                <div className="actions">
                  {d.status !== 'quarantined' && (
                    <button onClick={() => requestManualQuarantine(d.mac)}>Request Quarantine</button>
                  )}
                  {d.status === 'quarantined' && (
                    <button disabled>Quarantined</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="alerts-col">
          <h2>Alerts / Quarantine Requests</h2>
          <div className="alerts-list">
            {alerts.length === 0 ? <p>No alerts yet</p> : alerts.map(a => (
              <div className="alert-card" key={a._id}>
                <div>
                  <div className="muted">{new Date(a.timestamp).toLocaleString()}</div>
                  <strong>{a.type}</strong>
                  <div className="muted">{a.description}</div>
                  <div className="muted">Device: {a.device ? (a.device.mac || a.device._id) : 'Unknown'}</div>
                </div>

                {a.type === 'quarantine_request' && a.device && (
                  <div>
                    <button
                      onClick={() => requestApproveQuarantine(a.device._id)}
                      disabled={quarantineLoading[a.device._id]}
                    >
                      {quarantineLoading[a.device._id] ? 'Working...' : 'Approve Quarantine'}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
