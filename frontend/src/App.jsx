import React, { useEffect, useRef, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Devices from './pages/Devices';
import Alerts from './pages/Alerts';
import Whitelist from './pages/Whitelist';
import Quarantine from './pages/Quarantine';
import Settings from './pages/Settings';
import NET from 'vanta/dist/vanta.net.min.js';
import * as THREE from 'three';
import './App.css';
import Scanner from './pages/Scanner';
import { API_URL } from './config';

function App() {
  const [vantaEffect, setVantaEffect] = useState(null);
  const vantaRef = useRef(null);

  useEffect(() => {
    if (!vantaEffect && vantaRef.current) {
      setVantaEffect(
        NET({
          el: vantaRef.current,
          THREE: THREE,
          mouseControls: true,
          touchControls: true,
          minHeight: 600.0,
          minWidth: 800.0,
          scale: 0.0,
          scaleMobile: 0.0,
          lineColor: 0xff69b4,
          color: 0xff69b4,
          backgroundColor: 0x0f0f0f,
          showDots: true,
          maxDistance: 12.0,
          spacing: 30.0
        })
      );
    }
    return () => {
      if (vantaEffect) vantaEffect.destroy();
    };
  }, [vantaEffect]);

  // network signature watcher (Option B)
  useEffect(() => {
    let mounted = true;
    const POLL_MS = 5000;
    let lastCompact = null;

    const showToast = (msg) => {
      const el = document.createElement("div");
      el.textContent = msg;
      Object.assign(el.style, {
        position: "fixed",
        bottom: "20px",
        left: "20px",
        padding: "10px 14px",
        background: "#0b1220",
        color: "#fff",
        borderRadius: "8px",
        zIndex: 9999,
        boxShadow: "0 6px 18px rgba(0,0,0,0.6)"
      });
      document.body.appendChild(el);
      setTimeout(() => el.remove(), 5000);
    };

    const check = async () => {
      try {
        const res = await fetch(`${API_URL}/scanner2/network-signature`);
        if (!res.ok) return;
        const sig = await res.json();
        const compact = `${sig.npf || sig.interface || ""}|${sig.gateway || ""}|${sig.local_ip || ""}|${sig.public_ip || ""}`;
        if (!lastCompact) {
          lastCompact = compact;
          return;
        }
        if (compact !== lastCompact) {
          lastCompact = compact;
          // clear UI logs (Devices/Alerts will clear themselves on this)
          window.dispatchEvent(new Event("clear-logs"));
          // request backend+scanner reset (best-effort)
          try {
            await fetch(`${API_URL}/scanner2/reset`, { method: "POST" });
          } catch (e) {
            // ignore, still notify UI
            console.warn("Scanner reset request failed", e);
          }
          showToast("Network changed — scanning devices on the new network…");
        }
      } catch (err) {
        // ignore fetch errors
      }
    };

    check();
    const id = setInterval(() => { if (mounted) check(); }, POLL_MS);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  return (
    <div ref={vantaRef} className="vanta-bg">
      <Router>
        <Navbar />
        <div className="page-container">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/whitelist" element={<Whitelist />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/scanner" element={<Scanner />} />
          </Routes>
        </div>
      </Router>
    </div>
  );
}

export default App;
