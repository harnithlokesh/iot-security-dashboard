const express = require('express');
const router = express.Router();
const deviceController = require('../controllers/deviceController'); // <-- must match file exactly

router.get('/', deviceController.getDevices);
router.post('/', deviceController.addDevice);
router.put('/quarantine/:id', deviceController.quarantineDevice);
router.put('/release/:id', deviceController.releaseDevice);

module.exports = router;
