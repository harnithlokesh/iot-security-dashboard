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
exports.quarantineDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { status: 'quarantined' },
      { new: true }
    );
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: 'Failed to quarantine device' });
  }
};

// PUT release a device
exports.releaseDevice = async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { status: 'trusted' },
      { new: true }
    );
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: 'Failed to release device' });
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
