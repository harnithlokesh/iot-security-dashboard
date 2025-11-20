import React, { useEffect, useState } from "react";
import { API_URL } from "../config";
import "./Devices.css";

function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);

  // Fetch devices from backend
  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API_URL}/devices`);
      if (!res.ok) throw new Error("Fetch failed");
      const data = await res.json();
      setDevices(data);
    } catch (err) {
      console.error("Error fetching devices:", err);
    }
  };

  // Quarantine device
  const quarantineDevice = async (id) => {
    if (!window.confirm("Quarantine this device?")) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/devices/quarantine/${id}`, {
        method: "PUT",
      });
      const data = await res.json();
      alert(data.message || "🚫 Device quarantined!");
      fetchDevices();
    } catch (err) {
      console.error("Error quarantining device:", err);
      alert("❌ Failed to quarantine device");
    } finally {
      setLoading(false);
    }
  };

  // NEW: Whitelist device directly
  const whitelistDevice = async (device) => {
    if (!window.confirm("Add this device to whitelist?")) return;
    setLoading(true);

    try {
      const res = await fetch(`${API_URL}/whitelist/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: device.name,
          mac: device.mac,
          ip: device.ip,
        }),
      });

      const data = await res.json();
      alert(data.message || "✅ Device added to whitelist!");
      fetchDevices();
    } catch (err) {
      console.error("Whitelist error:", err);
      alert("❌ Failed to whitelist device");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000);

    const clearLogsHandler = () => {
      setDevices([]);
      setTimeout(fetchDevices, 1000);
    };

    window.addEventListener("clear-logs", clearLogsHandler);

    return () => {
      clearInterval(interval);
      window.removeEventListener("clear-logs", clearLogsHandler);
    };
  }, []);

  return (
    <div className="devices-page">
      <h1>Connected Devices</h1>

      {devices.length === 0 ? (
        <p>No devices found on the network.</p>
      ) : (
        <div className="devices-grid">
          {[...devices].reverse().map((device) => (
            <div className={`device-card ${device.status}`} key={device._id}>
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

                {/* NEW: Whitelist Button */}
                <button
                  className="whitelist-btn"
                  onClick={() => whitelistDevice(device)}
                  disabled={loading}
                >
                   Whitelist
                </button>

                {/* Existing Quarantine Button */}
                {device.status !== "quarantined" && (
                  <button
                    className="quarantine-btn"
                    onClick={() => quarantineDevice(device._id)}
                    disabled={loading}
                  >
                     Quarantine
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
