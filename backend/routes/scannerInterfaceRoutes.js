// backend/routes/scannerInterfaceRoutes.js
const express = require("express");
const router = express.Router();
const axios = require("axios");

const SCANNER_URL = process.env.SCANNER_API_URL || "http://localhost:9000";
const TOKEN = process.env.SCANNER_API_TOKEN || "supersecret_scanner_token";

const scannerRequest = (method, path, data = {}) => {
  return axios({
    method,
    url: `${SCANNER_URL}${path}`,
    data,
    headers: { Authorization: `Bearer ${TOKEN}` },
    timeout: 5000,
  });
};

router.get("/interfaces", async (req, res) => {
  try {
    const r = await scannerRequest("get", "/interfaces");
    res.json(r.data);
  } catch (err) {
    console.error("scanner interfaces error:", err.message || err);
    res.status(500).json({ error: "Failed to fetch scanner interfaces" });
  }
});

router.post("/start", async (req, res) => {
  try {
    const r = await scannerRequest("post", "/start", req.body);
    res.json(r.data);
  } catch (err) {
    console.error("scanner start error:", err.message || err);
    res.status(500).json({ error: "Failed to start scanner" });
  }
});

router.post("/stop", async (req, res) => {
  try {
    const r = await scannerRequest("post", "/stop");
    res.json(r.data);
  } catch (err) {
    console.error("scanner stop error:", err.message || err);
    res.status(500).json({ error: "Failed to stop scanner" });
  }
});

router.post("/reset", async (req, res) => {
  try {
    const r = await scannerRequest("post", "/reset");
    res.json(r.data);
  } catch (err) {
    console.error("scanner reset error:", err.message || err);
    res.status(500).json({ error: "Failed to reset scanner" });
  }
});

router.get("/network-signature", async (req, res) => {
  try {
    const r = await scannerRequest("get", "/network-signature");
    res.json(r.data);
  } catch (err) {
    console.error("scanner network-signature error:", err.message || err);
    res.status(500).json({ error: "Failed to fetch network signature" });
  }
});

module.exports = router;
