import React, { useState, useEffect } from "react";
import { API_URL } from "../config";

export default function InterfaceSelector() {
  const [interfaces, setInterfaces] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetchInterfaces();
  }, []);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch(`${API_URL}/scanner2/interfaces`);
      if (!res.ok) throw new Error("Failed to load");
      const data = await res.json();
      setInterfaces(data);
    } catch (err) {
      console.error("Failed to load interfaces:", err);
      setMessage("Failed to load interfaces");
    }
  };

  const start = async (iface) => {
    setLoading(true);
    setMessage("");
    try {
      const res = await fetch(`${API_URL}/scanner2/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: iface }),
      });
      if (!res.ok) throw new Error("start failed");
      const j = await res.json();
      setSelected(iface);
      // Tell UI to clear old logs immediately
      window.dispatchEvent(new Event("clear-logs"));
      setMessage(`Scanner started on ${iface}`);
    } catch (err) {
      console.error("start failed", err);
      setMessage("Failed to start scanner");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="device-card" style={{ marginBottom: 16 }}>
      <h3 style={{ margin: "0 0 8px 0" }}>Select Network Interface</h3>

      {message && <div style={{ marginBottom: 8 }}>{message}</div>}

      {interfaces.length === 0 ? (
        <p>Loading interfaces…</p>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {interfaces.map((it) => {
            const key = it.npf_name || it.name;
            return (
              <button
                key={key}
                className="quarantine-btn"
                disabled={loading}
                onClick={() => start(key)}
                style={{
                  textAlign: "left",
                  padding: "10px",
                  background: selected === key ? "#ff69b4" : undefined,
                }}
              >
                <div style={{ fontWeight: 600 }}>{it.name}</div>
                <div style={{ fontSize: 12 }}>{it.ip || "no ip"} — {it.isp || "ISP unknown"}</div>
              </button>
            );
          })}
        </div>
      )}

      <div style={{ marginTop: 10 }}>
        <button className="release-btn" onClick={fetchInterfaces} disabled={loading}>
          Refresh list
        </button>
      </div>
    </div>
  );
}
