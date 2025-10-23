// routes/quarantineRoutes.js
const express = require('express');
const router = express.Router();
const quarantineController = require('../controllers/quarantineController');

router.post('/request', quarantineController.requestQuarantine); // scanner -> record request
router.post('/approve/:id', quarantineController.approveQuarantine); // admin -> approve (device id)

module.exports = router;
