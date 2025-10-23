const express = require("express");
const router = express.Router();

const {
  getWhitelist,
  addWhitelistDevice,
  removeWhitelistDevice
} = require("../controllers/whitelistController");

// GET all whitelisted devices
router.get("/", getWhitelist);

// POST add a new device
router.post("/", addWhitelistDevice);

// DELETE a device by ID
router.delete("/:id", removeWhitelistDevice);

module.exports = router;
