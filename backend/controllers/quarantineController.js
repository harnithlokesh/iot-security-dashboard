// controllers/quarantineController.js
const Device = require('../models/Device');
const Alert = require('../models/Alert');

// scanner posts here to request a quarantine (records request as an alert)
exports.requestQuarantine = async (req, res) => {
  try {
    const { mac, deviceId } = req.body;
    let device = null;
    if (deviceId) device = await Device.findById(deviceId);
    else if (mac) device = await Device.findOne({ mac: mac.toLowerCase() });

    if (!device) return res.status(404).json({ error: 'Device not found' });

    const alert = new Alert({
      device: device._id,
      type: 'quarantine_request',
      description: `Scanner requested quarantine for ${device.mac}`
    });
    await alert.save();

    // create a "pendingQuarantine" flag on the device document for admin UI (optional)
    device.pendingQuarantine = true;
    await device.save();

    res.status(201).json({ message: 'Quarantine request recorded', alert });
  } catch (err) {
    console.error('requestQuarantine', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// admin approves the quarantine — backend performs the action (mark device quarantined)
exports.approveQuarantine = async (req, res) => {
  try {
    const { id } = req.params; // device id
    const device = await Device.findById(id);
    if (!device) return res.status(404).json({ error: 'Device not found' });

    // update device status
    device.status = 'quarantined';
    device.pendingQuarantine = false;
    await device.save();

    // create an alert recording the quarantine
    const alert = new Alert({
      device: device._id,
      type: 'quarantine',
      description: `Admin approved quarantine for ${device.mac}`
    });
    await alert.save();

    // TODO: here you could call a script, firewall rule, or network API to actually block the device
    // For now we just record the quarantine in DB and return success

    res.json({ message: 'Device quarantined', device, alert });
  } catch (err) {
    console.error('approveQuarantine', err);
    res.status(500).json({ error: 'Server error' });
  }
};
