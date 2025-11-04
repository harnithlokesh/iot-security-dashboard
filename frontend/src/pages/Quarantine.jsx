import React, { useEffect, useState } from "react";
import { API_URL } from "../config";

function Quarantine() {
  const [devices, setDevices] = useState([]);

  const fetchQuarantinedDevices = async () => {
    try {
      const res = await fetch(`${API_URL}/devices`);
      const data = await res.json();
      const quarantined = data.filter((d) => d.status === "quarantined");
      setDevices(quarantined);
    } catch (err) {
      console.error("Error fetching quarantined devices:", err);
    }
  };

  const releaseDevice = async (id) => {
    try {
      await fetch(`${API_URL}/devices/release/${id}`, { method: "PUT" });
      fetchQuarantinedDevices();
    } catch (err) {
      console.error("Error releasing device:", err);
    }
  };

  useEffect(() => {
    fetchQuarantinedDevices();
    const interval = setInterval(fetchQuarantinedDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="devices-page">
      <h1>Quarantined Devices</h1>
      {devices.length === 0 ? (
        <p>No quarantined devices</p>
      ) : (
        devices.map((device) => (
          <div className="device-card quarantined" key={device._id}>
            <div className="device-info">
              <h2>{device.name}</h2>
              <p>MAC: {device.mac}</p>
              <p>IP: {device.ip}</p>
              <p>Status: {device.status}</p>
            </div>
            <div className="device-actions">
              <button
                className="release-btn"
                onClick={() => releaseDevice(device._id)}
              >
                Release
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

export default Quarantine;
