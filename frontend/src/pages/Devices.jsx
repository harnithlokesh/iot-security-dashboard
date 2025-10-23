import React, { useEffect, useState } from "react";
import { API_URL } from "../config";

function Devices() {
  const [devices, setDevices] = useState([]);

  // Fetch devices from backend
  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API_URL}/devices`);
      const data = await res.json();
      setDevices(data);
    } catch (err) {
      console.error("Error fetching devices:", err);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  // Quarantine a device
  const quarantineDevice = async (id) => {
    try {
      await fetch(`${API_URL}/devices/quarantine/${id}`, { method: "PUT" });
      fetchDevices(); // Refresh the list
    } catch (err) {
      console.error("Error quarantining device:", err);
    }
  };

  // Release a device
  const releaseDevice = async (id) => {
    try {
      await fetch(`${API_URL}/devices/release/${id}`, { method: "PUT" });
      fetchDevices(); // Refresh the list
    } catch (err) {
      console.error("Error releasing device:", err);
    }
  };

  return (
    <div className="devices-page">
      <h1>Devices</h1>
      {devices.length === 0 ? (
        <p>No devices found</p>
      ) : (
        devices.map((device) => (
          <div className="device-card" key={device._id}>
            <div className="device-info">
              <h2>{device.name}</h2>
              <p>MAC: {device.mac}</p>
              <p>IP: {device.ip}</p>
              <p>
                Status:{" "}
                <span className={`status ${device.status}`}>
                  {device.status}
                </span>
              </p>
            </div>
            <div className="device-actions">
              {device.status !== "quarantined" && (
                <button
                  className="quarantine-btn"
                  onClick={() => quarantineDevice(device._id)}
                >
                  Quarantine
                </button>
              )}
              {device.status === "quarantined" && (
                <button
                  className="quarantine-btn"
                  onClick={() => releaseDevice(device._id)}
                >
                  Release
                </button>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

export default Devices;
