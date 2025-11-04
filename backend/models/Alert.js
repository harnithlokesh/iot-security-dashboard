const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  device: { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  type: { type: String, enum: ['unauthorized', 'quarantine', 'release','quarantine_request'], required: true },
  timestamp: { type: Date, default: Date.now },
  description: { type: String }
});

module.exports = mongoose.model('Alert', alertSchema);
