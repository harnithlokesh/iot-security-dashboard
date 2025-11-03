const express = require('express');
const router = express.Router();
const Device = require('../models/Device'); // assumes you already have a Device model


// Receive scan results from Python scanner
router.post('/results', async (req, res) => {
  try {
    const devices = req.body.devices || [];

    // Option 1: Replace all existing devices
    await Device.deleteMany({});
    await Device.insertMany(devices);

    console.log(`📡 Received ${devices.length} devices from scanner`);
    res.status(200).json({ message: 'Scan results stored successfully' });
  } catch (err) {
    console.error('❌ Error saving scan results:', err);
    res.status(500).json({ error: 'Failed to save scan results' });
  }
});

// Get all scanned devices
router.get('/devices', async (req, res) => {
  try {
    const devices = await Device.find();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching devices' });
  }
});

module.exports = router;
