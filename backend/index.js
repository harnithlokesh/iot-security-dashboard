const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');


require('dotenv').config();


// Import routes
const deviceRoutes = require('./routes/deviceRoutes');
const alertRoutes = require('./routes/alertRoutes');
const whitelistRoutes = require('./routes/whitelistRoutes');
const quarantineRoutes = require('./routes/quarantineRoutes');
const scannerRoutes = require('./routes/scannerRoutes');


const app = express(); // <-- app must be defined BEFORE using app.use()
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/devices', deviceRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/whitelist', whitelistRoutes);
app.use('/api/quarantine', quarantineRoutes);
app.use('/api/scanner', scannerRoutes);


// Test route
app.get('/', (req, res) => {
  res.send('IoT Security Backend Running');
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.use("/api/alerts", require("./routes/alertRoutes"));
app.use("/api/whitelist", require("./routes/whitelistRoutes"));


