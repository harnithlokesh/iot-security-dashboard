const mongoose = require("mongoose");

const whitelistSchema = new mongoose.Schema({
  deviceName: { type: String, required: true },
  macAddress: { type: String, required: true, unique: true },
  addedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Whitelist", whitelistSchema);
