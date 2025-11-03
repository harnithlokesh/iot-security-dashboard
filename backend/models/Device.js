


// backend/models/Device.js
const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  name: { type: String, default: 'Unknown' },
  mac: { type: String, required: true, unique: true },
  ip: { type: String, default: '' },
  status: { type: String, enum: ['trusted','rogue','quarantined'], default: 'rogue' },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  vendor: { type: String, default: '' },
  meta: { type: Object, default: {} }
}, { timestamps: true });

module.exports = mongoose.model('Device', DeviceSchema);
