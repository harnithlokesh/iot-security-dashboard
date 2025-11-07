import React, { useEffect, useState } from "react";
import "./Dashboard.css";
import { API_URL } from "../config";

function Dashboard() {
  const [stats, setStats] = useState({
    totalDevices: 0,
    trustedDevices: 0,
    rogueDevices: 0,
    quarantinedDevices: 0,
    alertsLast24h: 0,
  });

  const fetchStats = async () => {
    try {
      // Fetch devices
      const res = await fetch(`${API_URL}/devices`);
      const devices = await res.json();

      const trusted = devices.filter((d) => d.status === "trusted").length;
      const rogue = devices.filter((d) => d.status === "rogue").length;
      const quarantined = devices.filter((d) => d.status === "quarantined").length;
      const total = devices.length;

      // Fetch alerts
      const alertRes = await fetch(`${API_URL}/alerts`);
      const alerts = await alertRes.json();
      const last24h = alerts.filter(
        (a) => new Date(a.timestamp) > Date.now() - 24 * 60 * 60 * 1000
      ).length;

      setStats({
        totalDevices: total,
        trustedDevices: trusted,
        rogueDevices: rogue,
        quarantinedDevices: quarantined,
        alertsLast24h: last24h,
      });
    } catch (err) {
      console.error("Error fetching dashboard stats:", err);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000); // auto-refresh every 5s
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-page">
      <h1>Network Overview</h1>
      <div className="stats-grid">
        <div className="stat-card totalDevices">
          <h2>{stats.totalDevices}</h2>
          <p>Total Devices</p>
        </div>
        <div className="stat-card trustedDevices">
          <h2>{stats.trustedDevices}</h2>
          <p>Trusted Devices</p>
        </div>
        <div className="stat-card rogueDevices">
          <h2>{stats.rogueDevices}</h2>
          <p>Rogue Devices</p>
        </div>
        <div className="stat-card quarantinedDevices">
          <h2>{stats.quarantinedDevices}</h2>
          <p>Quarantined Devices</p>
        </div>
        <div className="stat-card alertsLast24h">
          <h2>{stats.alertsLast24h}</h2>
          <p>Alerts (Last 24h)</p>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
