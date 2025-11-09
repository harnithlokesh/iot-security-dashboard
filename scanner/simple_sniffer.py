import os
import time
import logging
from threading import Thread
from scapy.all import sniff, ARP
import requests

# -----------------------
# Config (or load from .env)
# -----------------------
SCAN_INTERFACE = r"\Device\NPF_{FB00E5D6-E77F-4277-90E7-769AB3DC5844}"
BACKEND_URL = "http://localhost:5000/api"
WHITELIST_FILE = "whitelist.txt"
QUARANTINE_ENABLED = True
DEBOUNCE_SECONDS = 3

# -----------------------
# Logger setup
# -----------------------
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.info("Scanner starting...")

# -----------------------
# Load whitelist
# -----------------------
whitelist = set()
if os.path.exists(WHITELIST_FILE):
    with open(WHITELIST_FILE, "r") as f:
        for line in f:
            whitelist.add(line.strip().lower())
logging.info(f"Whitelist loaded: {len(whitelist)} entries")

# -----------------------
# Connected devices tracking
# -----------------------
connected_devices = {}  # mac -> last_seen

# -----------------------
# Device handling
# -----------------------
def handle_packet(pkt):
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()

        # Debounce to avoid spamming
        now = time.time()
        last_seen = connected_devices.get(mac, 0)
        if now - last_seen < DEBOUNCE_SECONDS:
            return
        connected_devices[mac] = now

        if mac in whitelist:
            logging.info(f"Known device: {ip} -> {mac}")
        else:
            logging.info(f"Suspicious device detected: {ip} -> {mac}")
            if QUARANTINE_ENABLED:
                logging.info(f"Quarantine simulated for {mac}")
            # Send alert to backend
            try:
                resp = requests.post(f"{BACKEND_URL}/alerts", json={"mac": mac, "ip": ip})
                if resp.status_code == 200:
                    logging.info(f"Alert sent for {mac}")
                else:
                    logging.warning(f"Alert API returned {resp.status_code}: {resp.text}")
            except Exception as e:
                logging.error(f"Failed to report device {mac}: {e}")

# -----------------------
# Start sniffer in background
# -----------------------
def start_sniffer():
    logging.info(f"Starting sniffer on {SCAN_INTERFACE}")
    sniff(iface=SCAN_INTERFACE, store=False, prn=handle_packet)

sniffer_thread = Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

logging.info("Scanner started. Press Ctrl+C to stop.")

# Keep script alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    logging.info("Scanner stopping via Ctrl+C...")
