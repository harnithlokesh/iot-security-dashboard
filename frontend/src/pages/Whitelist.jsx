import React, { useEffect, useState } from "react";
import { API_URL } from "../config";

function Whitelist() {
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchTrusted = async () => {
    try {
      const res = await fetch(`${API_URL}/devices`);
      const data = await res.json();
      const trusted = data.filter((d) => d.status === "trusted");
      setTrustedDevices(trusted);
      setLoading(false);
    } catch (err) {
      console.error("Error fetching trusted devices:", err);
      setLoading(false);
    }
  };

  const removeFromWhitelist = async (id) => {
    try {
      await fetch(`${API_URL}/devices/quarantine/${id}`, { method: "PUT" });
      fetchTrusted();
    } catch (err) {
      console.error("Error removing from whitelist:", err);
    }
  };

  useEffect(() => {
    fetchTrusted();
    const interval = setInterval(fetchTrusted, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <p>Loading trusted devices...</p>;

  return (
    <div className="page-container">
      <h1>Whitelist (Trusted Devices)</h1>
      {trustedDevices.length === 0 ? (
        <p>No trusted devices</p>
      ) : (
        <table className="whitelist-table">
          <thead>
            <tr>
              <th>Device Name</th>
              <th>MAC</th>
              <th>IP</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {trustedDevices.map((device) => (
              <tr key={device._id}>
                <td>{device.name || "Unnamed Device"}</td>
                <td>{device.mac}</td>
                <td>{device.ip}</td>
                <td>
                  <button
                    className="remove-btn"
                    onClick={() => removeFromWhitelist(device._id)}
                  >
                    Remove / Quarantine
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Whitelist;
