import React from 'react';
import { Link } from 'react-router-dom';
import './Navbar.css';

function Navbar() {
  return (
    <nav className="navbar">
      <h2 className="logo">IoT Monitor</h2>
      <ul>
        <li><Link to="/">Dashboard</Link></li>
        <li><Link to="/devices">Devices</Link></li>
        <li><Link to="/alerts">Alerts</Link></li>
        <li><Link to="/whitelist">Whitelist</Link></li>
        <li><Link to="/quarantine">Quarantine</Link></li>
        <li><Link to="/settings">Settings</Link></li>
      </ul>
    </nav>
  );
}

export default Navbar;
