// controllers/alertController.js
const Alert = require('../models/Alert');
const Device = require('../models/Device');

// GET all alerts (existing)
exports.getAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().populate('device').sort({ timestamp: -1 });
    res.json(alerts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
};

// POST create alert (used by scanner)
exports.createAlert = async (req, res) => {
  try {
    const { device: deviceId, mac, type, description } = req.body;

    let device = null;
    if (deviceId) {
      device = await Device.findById(deviceId);
    } else if (mac) {
      device = await Device.findOne({ mac: mac.toLowerCase() });
    }

    const alert = new Alert({
      device: device ? device._id : undefined,
      type: type || 'unauthorized',
      description: description || '',
    });

    await alert.save();

    res.status(201).json(alert);
  } catch (err) {
    console.error('createAlert error', err);
    res.status(500).json({ error: 'Failed to create alert' });
  }
};
