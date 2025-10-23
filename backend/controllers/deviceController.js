const Device = require('../models/Device');
const Alert = require('../models/Alert');

// Get all devices
exports.getDevices = async (req, res) => {
  try {
    const devices = await Device.find();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Add a new device
exports.addDevice = async (req, res) => {
  try {
    const { name, mac, ip, status } = req.body;
    const device = new Device({ name, mac, ip, status });
    await device.save();
    res.status(201).json(device);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Quarantine a device
exports.quarantineDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(req.params.id, { status: 'quarantined' }, { new: true });
    const alert = new Alert({ device: device._id, type: 'quarantine', description: 'Device quarantined' });
    await alert.save();
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Release a device from quarantine
exports.releaseDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(req.params.id, { status: 'trusted' }, { new: true });
    const alert = new Alert({ device: device._id, type: 'release', description: 'Device released' });
    await alert.save();
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
// GET /api/alerts
const getAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ timestamp: -1 }); // newest first
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};
