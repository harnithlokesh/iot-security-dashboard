const Device = require('../models/Device');
const Alert = require('../models/Alert');

// GET all devices
exports.getDevices = async (req, res) => {
  try {
    const devices = await Device.find();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
};

// POST add/update device
exports.addDevice = async (req, res) => {
  try {
    const { mac, ip, name, status } = req.body;

    let device = await Device.findOne({ mac });
    if (device) {
      device.ip = ip || device.ip;
      device.status = status || device.status;
      device.last_seen = new Date();
      await device.save();
      return res.status(200).json(device);
    } else {
      const newDevice = new Device({ mac, ip, name, status });
      await newDevice.save();
      return res.status(201).json(newDevice);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add device' });
  }
};

// PUT quarantine a device
const axios = require("axios");

exports.quarantineDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { status: "quarantined" },
      { new: true }
    );

    // Notify scanner
    try {
      await axios.post("http://127.0.0.1:9000/quarantine", {
  mac: device.mac,
  ip: device.ip,
}, {
  headers: { Authorization: "Bearer supersecret_scanner_token" } // must match .env token
});

    } catch (err) {
      console.error("Failed to notify scanner:", err.message);
    }

    res.json(device);
  } catch (err) {
    res.status(500).json({ error: "Failed to quarantine device" });
  }
};


// PUT release a device
exports.releaseDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { status: "trusted" },
      { new: true }
    );

    try {
      await axios.post("http://localhost:9000/whitelist", 
        { mac: device.mac },
        { headers: { Authorization: "Bearer supersecret_scanner_token" } }
      );
    } catch (err) {
      console.error("Failed to notify scanner (release):", err.message);
    }

    res.json(device);
  } catch (err) {
    res.status(500).json({ error: "Failed to release device" });
  }
};

