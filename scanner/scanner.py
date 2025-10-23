#!/usr/bin/env python3
"""
scanner.py
Passive LAN device scanner (ARP + DHCP) that reports devices to backend.
Works on Windows (with Npcap) and Linux. Run as Administrator/root.
"""

import os
import time
import logging
import sys
import threading
from dotenv import load_dotenv
from scapy.all import sniff, ARP, BOOTP, DHCP, Ether, UDP
import requests

# Load config
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000/api")
INTERFACE = os.getenv("SCAN_INTERFACE", None)   # e.g. "Wi‑Fi" or "Ethernet" on Windows, or "wlan0"/"eth0" on Linux
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "whitelist.txt")
LOG_FILE = os.getenv("LOG_FILE", "scanner.log")
QUARANTINE_ENABLED = os.getenv("QUARANTINE_ENABLED", "false").lower() in ("1", "true", "yes")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "3"))

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# In-memory caches
devices = {}            # mac -> { ip, vendor (optional), first_seen, last_seen }
last_seen_times = {}    # mac -> timestamp (for debounce)
stop_sniffing = False   # global flag to stop sniffing

# ------------------ Helper functions ------------------

def load_local_whitelist(path):
    s = set()
    if os.path.isfile(path):
        with open(path, "r") as f:
            for line in f:
                v = line.strip()
                if v:
                    s.add(v.lower())
    return s

local_whitelist = load_local_whitelist(WHITELIST_FILE)
logging.info(f"Local whitelist entries: {len(local_whitelist)}")

def should_process(mac):
    now = time.time()
    last = last_seen_times.get(mac, 0)
    if now - last >= DEBOUNCE_SECONDS:
        last_seen_times[mac] = now
        return True
    return False

def report_device(mac, ip=None, name=None):
    payload = {
        "name": name or "Unknown",
        "mac": mac,
        "ip": ip or "",
        "status": "trusted" if mac.lower() in local_whitelist else "rogue"
    }
    try:
        r = requests.post(f"{BACKEND_URL}/devices", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info(f"Reported device: {mac} {ip} ({payload['status']})")
            return r.json()
        else:
            logging.warning(f"Failed to report device {mac}: {r.status_code} {r.text}")
            return None
    except Exception as e:
        logging.error(f"Error reporting device {mac}: {e}")
        return None

def create_alert(device_id=None, mac=None, alert_type="unauthorized", description=""):
    payload = {"type": alert_type, "description": description}
    if device_id:
        payload["device"] = device_id
    elif mac:
        payload["mac"] = mac
    try:
        r = requests.post(f"{BACKEND_URL}/alerts", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info(f"Alert created: {alert_type} for {device_id or mac}")
            return r.json()
        else:
            logging.warning(f"Alert API returned {r.status_code}: {r.text}")
            return None
    except Exception as e:
        logging.error(f"Error creating alert: {e}")
        return None

def request_quarantine(device_id=None, mac=None):
    if not QUARANTINE_ENABLED:
        logging.info("Quarantine is disabled (QUARANTINE_ENABLED=false).")
        return None
    payload = {}
    if device_id:
        payload["deviceId"] = device_id
    elif mac:
        payload["mac"] = mac
    try:
        r = requests.post(f"{BACKEND_URL}/quarantine/request", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info(f"Quarantine requested for {device_id or mac}")
            return r.json()
        else:
            logging.warning(f"Quarantine API returned {r.status_code}: {r.text}")
            return None
    except Exception as e:
        logging.error(f"Error requesting quarantine: {e}")
        return None

# ------------------ Packet handlers ------------------

def handle_arp(pkt):
    try:
        if ARP in pkt and pkt[ARP].op in (1,2):
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
            if not mac:
                return
            mac = mac.lower()
            if not should_process(mac):
                return
            now = time.time()
            if mac in devices:
                devices[mac]["ip"] = ip or devices[mac].get("ip")
                devices[mac]["last_seen"] = now
            else:
                devices[mac] = {"mac": mac, "ip": ip, "first_seen": now, "last_seen": now}
                backend_obj = report_device(mac, ip)
                if mac not in local_whitelist:
                    device_id = backend_obj.get("_id") if backend_obj and isinstance(backend_obj, dict) else None
                    create_alert(device_id=device_id, mac=mac, alert_type="unauthorized",
                                 description=f"Unauthorized device detected (ARP): {mac} {ip}")
                    if QUARANTINE_ENABLED:
                        request_quarantine(device_id=device_id, mac=mac)
    except Exception as e:
        logging.error(f"handle_arp error: {e}")

def handle_dhcp(pkt):
    try:
        if BOOTP in pkt:
            chaddr = pkt[BOOTP].chaddr
            yiaddr = pkt[BOOTP].yiaddr
            if isinstance(chaddr, (bytes, bytearray)):
                mac = ':'.join(f"{b:02x}" for b in chaddr[:6])
            else:
                mac = str(chaddr)
            mac = mac.lower()
            ip = yiaddr
            if not should_process(mac):
                return
            now = time.time()
            if mac in devices:
                devices[mac]["ip"] = ip or devices[mac].get("ip")
                devices[mac]["last_seen"] = now
            else:
                devices[mac] = {"mac": mac, "ip": ip, "first_seen": now, "last_seen": now}
                backend_obj = report_device(mac, ip)
                if mac not in local_whitelist:
                    device_id = backend_obj.get("_id") if backend_obj and isinstance(backend_obj, dict) else None
                    create_alert(device_id=device_id, mac=mac, alert_type="unauthorized",
                                 description=f"Unauthorized device detected (DHCP): {mac} {ip}")
                    if QUARANTINE_ENABLED:
                        request_quarantine(device_id=device_id, mac=mac)
    except Exception as e:
        logging.error(f"handle_dhcp error: {e}")

def pkt_handler(pkt):
    try:
        if ARP in pkt:
            handle_arp(pkt)
        elif DHCP in pkt or (pkt.haslayer(UDP) and (pkt[UDP].sport in (67,68) or pkt[UDP].dport in (67,68))):
            handle_dhcp(pkt)
    except Exception as e:
        logging.error(f"pkt_handler error: {e}")

# ------------------ Sniffer ------------------

def start_sniff():
    global stop_sniffing
    logging.info(f"Starting scanner. Interface={INTERFACE or 'auto'} QuarantineEnabled={QUARANTINE_ENABLED}")

    def sniff_thread():
        sniff_kwargs = {"prn": pkt_handler, "store": False, "stop_filter": lambda x: stop_sniffing}
        if INTERFACE:
            sniff_kwargs["iface"] = INTERFACE
        sniff(**sniff_kwargs)

    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

    try:
        while not stop_sniffing:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Scanner stopping via Ctrl+C...")
        stop_sniffing = True
        t.join()

# ------------------ Main ------------------

if __name__ == "__main__":
    try:
        logging.info("Scanner starting...")
        start_sniff()
    except Exception as e:
        logging.error(f"Scanner fatal error: {e}")
        sys.exit(1)
