import React, { useEffect, useState } from "react";
import "./Dashboard.css";
import { API_URL } from "../config";

function Dashboard() {
  const initialStats = {
    totalDevices: 0,
    trustedDevices: 0,   // comes from whitelist now
    rogueDevices: 0,
    quarantinedDevices: 0,
    alertsLast24h: 0,
  };

  const [stats, setStats] = useState(initialStats);
  const [loading, setLoading] = useState(false);

  const fetchStats = async () => {
    try {
      setLoading(true);

      // Fetch devices + alerts + whitelist in parallel
      const [deviceRes, alertRes, whitelistRes] = await Promise.all([
        fetch(`${API_URL}/devices`),
        fetch(`${API_URL}/alerts`),
        fetch(`${API_URL}/whitelist`)
      ]);

      const devices = await deviceRes.json();
      const alerts = await alertRes.json();
      const whitelist = await whitelistRes.json();   // <-- NEW!

      const rogue = devices.filter((d) => d.status === "rogue").length;
      const quarantined = devices.filter((d) => d.status === "quarantined").length;
      const total = devices.length;

      const last24h = alerts.filter(
        (a) =>
          new Date(a.timestamp).getTime() >
          Date.now() - 24 * 60 * 60 * 1000
      ).length;

      // trustedDevices = whitelist count
      setStats({
        totalDevices: total,
        trustedDevices: whitelist.length,    // <-- FIXED!
        rogueDevices: rogue,
        quarantinedDevices: quarantined,
        alertsLast24h: last24h,
      });

      setLoading(false);
    } catch (err) {
      console.error("Error fetching dashboard stats:", err);
      setLoading(false);
    }
  };

  const forceRefresh = async () => {
    setLoading(true);
    setStats(initialStats);

    try {
      await fetch(`${API_URL}/refresh-scan`, { method: "POST" });
    } catch (err) {
      console.error("Error triggering refresh scan:", err);
    }

    await fetchStats();
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-page">
      <h1>Network Overview</h1>

      <button
        onClick={forceRefresh}
        className="refresh-btn"
        disabled={loading}
      >
        {loading ? "Scanning..." : "Force Refresh Scan"}
      </button>

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
