const Whitelist = require('../models/Whitelist');

// Get all whitelisted devices
exports.getWhitelist = async (req, res) => {
  try {
    const devices = await Whitelist.find().sort({ addedAt: -1 });
    res.json(devices);
  } catch (err) {
    console.error("Error fetching whitelist:", err);
    res.status(500).json({ error: "Failed to fetch whitelist" });
  }
};

// Add device to whitelist
exports.addWhitelistDevice = async (req, res) => {
  try {
    const { deviceName, macAddress } = req.body;

    if (!deviceName || !macAddress) {
      return res.status(400).json({ error: "Device name and MAC address are required" });
    }

    // Prevent duplicates
    const existing = await Whitelist.findOne({ macAddress });
    if (existing) {
      return res.status(400).json({ error: "Device already whitelisted" });
    }

    const device = new Whitelist({ deviceName, macAddress });
    await device.save();

    res.status(201).json(device);
  } catch (err) {
    console.error("Error adding device to whitelist:", err);
    res.status(500).json({ error: "Failed to add device to whitelist" });
  }
};

// Remove device from whitelist
exports.removeWhitelistDevice = async (req, res) => {
  try {
    const device = await Whitelist.findByIdAndDelete(req.params.id);
    if (!device) return res.status(404).json({ error: "Device not found" });

    res.json({ message: "Device removed from whitelist" });
  } catch (err) {
    console.error("Error removing device from whitelist:", err);
    res.status(500).json({ error: "Failed to remove device from whitelist" });
  }
};
