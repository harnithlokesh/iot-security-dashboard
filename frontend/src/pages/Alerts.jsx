import React, { useEffect, useState } from "react";
import "./Alerts.css";
import { API_URL } from "../config";

function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_URL}/alerts`);
      const data = await res.json();
      // Reverse order so newest on top
      setAlerts(data.reverse());
      setLoading(false);
    } catch (err) {
      console.error("Error fetching alerts:", err);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000); // refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) return <p>Loading alerts...</p>;

  return (
    <div className="alerts-page">
      <h1>Alerts & Logs</h1>
      {alerts.length > 0 ? (
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>MAC Address</th>
              <th>Event</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert._id}>
                <td>{new Date(alert.timestamp).toLocaleString()}</td>
                <td>{alert.device?.name || "Unknown Device"}</td>
                <td>{alert.device?.mac || "N/A"}</td>
                <td>{alert.type}</td>
                <td>{alert.description || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No alerts yet</p>
      )}
    </div>
  );
}

export default Alerts;
