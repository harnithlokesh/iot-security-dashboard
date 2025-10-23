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
    lineColor: 0xff69b4,       // Pink lines
    color: 0xff69b4,           // Dots color (optional)
    backgroundColor: 0x0f0f0f, // Dark background
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
