const Device = require('../models/Device');
const Alert = require('../models/Alert');
const axios = require("axios");

// GET all devices
exports.getDevices = async (req, res) => {
  try {
    const devices = await Device.find();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
};

// POST add/update device (upsert)
exports.addDevice = async (req, res) => {
  try {
    const { mac, ip, name, status, router_ip, network_signature } = req.body;

    if (!mac || !network_signature) {
      return res.status(400).json({ error: "mac and network_signature required" });
    }

    // Upsert device (create or update)
    const device = await Device.findOneAndUpdate(
      { mac: mac.toLowerCase(), network_signature },
      {
        $set: {
          ip,
          name: name || "Unknown",
          status: status || "rogue",
          router_ip,
          lastSeen: new Date()
        },
        $setOnInsert: { firstSeen: new Date() }
      },
      { new: true, upsert: true }
    );

    res.status(200).json(device);

  } catch (err) {
    console.error("addDevice error:", err);
    res.status(500).json({ error: 'Failed to add/update device' });
  }
};

// PUT quarantine a device
exports.quarantineDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { status: "quarantined" },
      { new: true }
    );

    if (!device) return res.status(404).json({ error: "Device not found" });

    // Notify scanner
    try {
      await axios.post(`${process.env.SCANNER_API_URL}/quarantine`, {
        mac: device.mac,
        ip: device.ip,
      }, {
        headers: { Authorization: "Bearer " + process.env.SCANNER_API_TOKEN }
      });
      console.log(`Scanner notified to quarantine ${device.mac}`);
    } catch (err) {
      console.error("Failed to notify scanner:", err.message);
    }

    // Create alert locally (use allowed type)
    await Alert.create({
      device: device._id,
      type: "quarantine",
      description: `Quarantine requested for ${device.mac}`
    });

    res.json(device);
  } catch (err) {
    console.error(err);
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

    if (!device) return res.status(404).json({ error: "Device not found" });

    try {
      await axios.post(`${process.env.SCANNER_API_URL}/release`, 
        { ip: device.ip },
        { headers: { Authorization: "Bearer " + process.env.SCANNER_API_TOKEN } }
      );
      console.log(`Scanner notified to release ${device.ip}`);
    } catch (err) {
      console.error("Failed to notify scanner (release):", err.message);
    }

    await Alert.create({
      device: device._id,
      type: "release",
      description: `Device released ${device.mac}`
    });

    res.json(device);
  } catch (err) {
    console.error("Release error:", err.message);
    res.status(500).json({ error: "Failed to release device" });
  }
};

// DELETE all devices (reset)
exports.resetDevices = async (req, res) => {
  try {
    await Device.deleteMany({});
    return res.json({ success: true, message: "All devices removed" });
  } catch (err) {
    console.error("resetDevices error:", err);
    return res.status(500).json({ error: "Failed to reset devices" });
  }
};

// POST refresh scan (remove devices not in current network)
exports.refreshScan = async (req, res) => {
  try {
    const { network_signature } = req.body;
    if (!network_signature) {
      return res.status(400).json({ error: "network_signature is required" });
    }

    console.log("Manual scan triggered. Resetting old devices and alerts...");

    // Remove devices not part of current network
    await Device.deleteMany({ network_signature: { $ne: network_signature } });

    // Remove alerts not part of current network (ensure enum is correct)
    await Alert.deleteMany({ network_signature: { $ne: network_signature }, type: { $in: ["quarantine", "release", "unauthorized"] } });

    res.json({
      success: true,
      message: "Old devices removed. Ready for new scan on current network."
    });
  } catch (err) {
    console.error("Refresh scan error:", err);
    res.status(500).json({ error: "Failed to refresh scan" });
  }
};
