// frontend/src/pages/Whitelist.jsx
import React, { useEffect, useState } from "react";
import { API_URL } from "../config";

function Whitelist() {
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchWhitelist = async () => {
    try {
      const res = await fetch(`${API_URL}/whitelist`);
      const data = await res.json();
      setWhitelist(data);  // actual whitelist collection
      setLoading(false);
    } catch (err) {
      console.error("Error fetching whitelist:", err);
      setLoading(false);
    }
  };

  // Remove device from whitelist
  const removeFromWhitelist = async (id) => {
    if (!window.confirm("Remove this device from whitelist?")) return;
    try {
      await fetch(`${API_URL}/whitelist/${id}`, { method: "DELETE" });
      fetchWhitelist();
    } catch (err) {
      console.error("Error removing from whitelist:", err);
    }
  };

  useEffect(() => {
    fetchWhitelist();
    const interval = setInterval(fetchWhitelist, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <p>Loading whitelist...</p>;

  return (
    <div className="page-container">
      <h1>Whitelist</h1>

      {whitelist.length === 0 ? (
        <p>No whitelisted devices found.</p>
      ) : (
        <table className="whitelist-table">
          <thead>
            <tr>
              <th>Device Name</th>
              <th>MAC</th>
              <th>IP</th>
              <th>Added</th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            {[...whitelist].reverse().map((device) => (
              <tr key={device._id}>
                <td>{device.deviceName}</td>
                <td>{device.macAddress}</td>
                <td>{device.ipAddress || "N/A"}</td>
                <td>{new Date(device.addedAt).toLocaleString()}</td>

                <td>
                  <button
                    className="remove-btn"
                    onClick={() => removeFromWhitelist(device._id)}
                  >
                    Remove
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
