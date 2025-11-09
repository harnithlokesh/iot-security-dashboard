import React, { useEffect, useState } from "react";
import { API_URL } from "../config";
import "./Devices.css"; // optional, for button styling

function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);

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

  // Quarantine a device
  const quarantineDevice = async (id) => {
    if (!window.confirm("Are you sure you want to quarantine this device?")) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/devices/quarantine/${id}`, { method: "PUT" });
      const data = await res.json();
      alert(data.message || "✅ Device quarantined successfully!");
      fetchDevices(); // Refresh the list
    } catch (err) {
      console.error("Error quarantining device:", err);
      alert("❌ Failed to quarantine device");
    } finally {
      setLoading(false);
    }
  };

  // Release a device
  const releaseDevice = async (id) => {
    if (!window.confirm("Release this quarantined device?")) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/devices/release/${id}`, { method: "PUT" });
      const data = await res.json();
      alert(data.message || "✅ Device released successfully!");
      fetchDevices(); // Refresh the list
    } catch (err) {
      console.error("Error releasing device:", err);
      alert("❌ Failed to release device");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000); // auto-refresh every 5 sec
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="devices-page">
      <h1>Connected Devices</h1>

      {devices.length === 0 ? (
        <p>No devices found on the network.</p>
      ) : (
        <div className="devices-grid">
          {[...devices].reverse().map((device) => (

            <div
              className={`device-card ${device.status}`}
              key={device._id}
            >
              <div className="device-info">
                <h2>{device.name || "Unknown Device"}</h2>
                <p><strong>MAC:</strong> {device.mac}</p>
                <p><strong>IP:</strong> {device.ip || "N/A"}</p>
                <p>
                  <strong>Status:</strong>{" "}
                  <span className={`status ${device.status}`}>
                    {device.status.toUpperCase()}
                  </span>
                </p>
              </div>

              <div className="device-actions">
                {device.status !== "quarantined" ? (
                  <button
                    className="quarantine-btn"
                    onClick={() => quarantineDevice(device._id)}
                    disabled={loading}
                  >
                    🚫 Quarantine
                  </button>
                ) : (
                  <button
                    className="release-btn"
                    onClick={() => releaseDevice(device._id)}
                    disabled={loading}
                  >
                    ✅ Release
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default Devices;
