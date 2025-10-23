import React, { useEffect, useState } from "react";
import "./Alerts.css";
import { API_URL } from "../config"; // optional for future backend

function Alerts() {
  // For now, using mock alerts
  const [alerts, setAlerts] = useState([
    {
      time: "2025-10-15 10:45",
      device: "Unknown IoT Device",
      mac: "FF:EE:DD:CC:BB:02",
      type: "Rogue device detected",
    },
    {
      time: "2025-10-15 09:15",
      device: "Smart Plug",
      mac: "AA:BB:CC:11:22:33",
      type: "Device quarantined",
    },
    {
      time: "2025-10-14 22:30",
      device: "Router",
      mac: "11:22:33:44:55:66",
      type: "ARP spoofing detected",
    },
  ]);

  // Example of future backend integration
  /*
  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch(`${API_URL}/alerts`);
        const data = await res.json();
        setAlerts(data);
      } catch (err) {
        console.error("Error fetching alerts:", err);
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);
  */

  return (
    <div className="alerts-page">
      <h1>Alerts & Logs</h1>
      {alerts && alerts.length > 0 ? (
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>MAC Address</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert, index) => (
              <tr key={index}>
                <td>{alert.time}</td>
                <td>{alert.device}</td>
                <td>{alert.mac}</td>
                <td>{alert.type}</td>
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
