const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController'); // <-- must match file exactly

router.get('/', deviceController.getDevices);
router.post('/', deviceController.addDevice);
router.put('/quarantine/:id', deviceController.quarantineDevice);
router.put('/release/:id', deviceController.releaseDevice);

router.delete("/", async (req, res) => {
  try {
    const Device = require("../models/Device");
    await Device.deleteMany({});
    res.json({ message: "All devices deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete devices" });
  }
});

module.exports = router;
