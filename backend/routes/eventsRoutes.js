// backend/routes/eventsRoutes.js
const express = require("express");
const router = express.Router();
const Alert = require("../models/Alert");

router.post("/network-changed", async (req, res) => {
  try {
    const message = req.body.message || "network_changed";
    // create a backend alert (optional)
    await Alert.create({ type: "network", description: "Network changed — scanner restarted" });
    return res.json({ ok: true });
  } catch (err) {
    console.error("events network-changed error:", err);
    return res.status(500).json({ error: "failed" });
  }
});

module.exports = router;
