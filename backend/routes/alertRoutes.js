// routes/alertRoutes.js
const express = require('express');
const router = express.Router();
const alertController = require('../controllers/alertController');

router.get('/', alertController.getAlerts);
router.post('/', alertController.createAlert);

const Alert = require("../models/Alert");

exports.getAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ timestamp: -1 });
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
};

exports.createAlert = async (req, res) => {
  try {
    const { device, mac, type, description } = req.body;
    const alert = new Alert({ device: device || null, type, description });
    await alert.save();
    res.status(201).json(alert);
  } catch (err) {
    console.error("createAlert error:", err);
    res.status(500).json({ error: 'Failed to create alert' });
  }
};

module.exports = router;
