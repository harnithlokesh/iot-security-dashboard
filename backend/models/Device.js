const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mac: { type: String, required: true, unique: true },
  ip: { type: String },
  status: { type: String, enum: ['trusted', 'rogue', 'quarantined'], default: 'rogue' },
  lastSeen: { type: Date, default: Date.now },
  pendingQuarantine: { type: Boolean, default: false }
});


module.exports = mongoose.model('Device', deviceSchema);
