import React from "react";
import InterfaceSelector from "../components/InterfaceSelector";
import "./Settings.css";

function Settings() {
  return (
    <div className="settings-page">
      <h1 className="settings-title">System Settings</h1>
      <p className="settings-sub">
        Configure network monitoring, interface selection, and notifications.
      </p>

      {/* ---- Interface Selector Card ---- */}
      <div className="settings-card">
        <h2>Scanner Network Interface</h2>
        <p>Select which Wi-Fi/Ethernet interface the scanner should monitor.</p>
        <div className="settings-card-actions">
          <InterfaceSelector />
        </div>
      </div>

      {/* ---- Notifications Settings ---- */}
      <div className="settings-card">
        <h2>Alert Notifications</h2>
        <p>Receive notifications when rogue devices or anomalies are detected.</p>
        <div className="settings-card-actions">
          <button className="toggle-btn">Enable / Disable</button>
        </div>
      </div>

      {/* ---- Future Expansion ---- */}
      <div className="settings-card">
        <h2>Scanner Options</h2>
        <p>Modify scanner parameters such as debounce, whitelist refresh, etc.</p>
        <div className="settings-card-actions">
          <button className="secondary-btn">Coming Soon</button>
        </div>
      </div>
    </div>
  );
}

export default Settings;
