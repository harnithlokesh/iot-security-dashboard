  const express = require("express");
  const router = express.Router();

  const {
    getWhitelist,
    addWhitelistDevice,
    removeWhitelistDevice
  } = require("../controllers/whitelistController");

  // GET all whitelisted devices
  router.get("/", getWhitelist);

  // POST add new whitelisted device
  router.post("/add", addWhitelistDevice);  // ⭐ better semantic route

  // DELETE a device by ID
  router.delete("/:id", removeWhitelistDevice);

  module.exports = router;
