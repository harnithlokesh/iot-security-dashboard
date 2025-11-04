#!/usr/bin/env python3
"""
scanner_service.py

A scanner service that:
- runs a passive ARP/DHCP scanner in background
- exposes a Flask HTTP API to control and query the scanner
- reports discovered devices to the main backend (BACKEND_URL)
- supports local whitelist and quarantine requests

Run:
    (venv) python scanner_service.py

Make sure you installed requirements:
    pip install scapy flask requests python-dotenv netaddr
"""

import os
import time
import logging
import sys
import threading
import signal
import json
from functools import wraps
from dotenv import load_dotenv
from scapy.all import sniff, ARP, BOOTP, DHCP, UDP, get_if_list, get_if_addr
import requests
from flask import Flask, request, jsonify, abort
#from quarantine import quarantine_device, release_device  # we'll make this next


# ---- Load config ----
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000/api")
SCAN_INTERFACE = os.getenv("SCAN_INTERFACE", "")  # raw NPF name or empty for auto
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "whitelist.txt")
LOG_FILE = os.getenv("LOG_FILE", "scanner_service.log")
QUARANTINE_ENABLED = os.getenv("QUARANTINE_ENABLED", "false").lower() in ("1", "true", "yes")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "3"))
SERVICE_PORT = int(os.getenv("SCANNER_SERVICE_PORT", "9000"))
API_AUTH_TOKEN = os.getenv("SCANNER_API_TOKEN", "changeme")  # simple token auth for local API

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# ---- Flask app ----
app = Flask(__name__)

# ---- Global state ----
devices = {}         # mac -> { mac, ip, first_seen, last_seen, status }
last_seen_times = {} # mac -> timestamp (debounce)
local_whitelist = set()
scanner_thread = None
stop_sniff_flag = threading.Event()
scanner_lock = threading.Lock()
sniff_iface = SCAN_INTERFACE or None
quarantined_devices = set()

# ---- Helper: auth decorator ----
def require_token(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = None
        # Accept token in header or as ?token= query param
        if "Authorization" in request.headers:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.split(None, 1)[1]
        if not token:
            token = request.args.get("token", None)
        if token != API_AUTH_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped

# ---- Utility functions ----
def load_local_whitelist(path=WHITELIST_FILE):
    s = set()
    if os.path.isfile(path):
        with open(path, "r") as f:
            for line in f:
                v = line.strip().lower()
                if v:
                    s.add(v)
    return s

def save_local_whitelist(path=WHITELIST_FILE):
    with open(path, "w") as f:
        for mac in sorted(local_whitelist):
            f.write(mac + "\n")

def should_process(mac):
    now = time.time()
    last = last_seen_times.get(mac, 0)
    if now - last >= DEBOUNCE_SECONDS:
        last_seen_times[mac] = now
        return True
    return False

def report_device_to_backend(mac, ip=None, name=None):
    payload = {
        "name": name or "Unknown",
        "mac": mac,
        "ip": ip or "",
        "status": "trusted" if mac.lower() in local_whitelist else "rogue"
    }
    try:
        r = requests.post(f"{BACKEND_URL}/devices", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info("Reported device to backend: %s %s", mac, ip)
            return r.json()
        else:
            logging.warning("Backend devices POST returned %s: %s", r.status_code, r.text)
    except Exception as e:
        logging.error("Error reporting device to backend: %s", e)
    return None

def create_alert_on_backend(device_id=None, mac=None, alert_type="unauthorized", description=""):
    payload = {"type": alert_type, "description": description}
    if device_id:
        payload["device"] = device_id
    elif mac:
        payload["mac"] = mac
    try:
        r = requests.post(f"{BACKEND_URL}/alerts", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info("Created alert on backend for %s", mac or device_id)
            return r.json()
        else:
            logging.warning("Alert API returned %s: %s", r.status_code, r.text)
    except Exception as e:
        logging.error("Error creating alert on backend: %s", e)
    return None

def request_quarantine_on_backend(device_id=None, mac=None):
    payload = {}
    if device_id:
        payload["deviceId"] = device_id
    elif mac:
        payload["mac"] = mac
    try:
        r = requests.post(f"{BACKEND_URL}/quarantine/request", json=payload, timeout=5)
        if r.status_code in (200,201):
            logging.info("Requested quarantine on backend for %s", mac or device_id)
            return r.json()
        else:
            logging.warning("Quarantine request returned %s: %s", r.status_code, r.text)
    except Exception as e:
        logging.error("Error requesting quarantine on backend: %s", e)
    return None

# ---- Packet handling (reused from your scanner) ----
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
            with scanner_lock:
                if mac in devices:
                    devices[mac]["ip"] = ip or devices[mac].get("ip")
                    devices[mac]["last_seen"] = now
                else:
                    devices[mac] = {
                        "mac": mac,
                        "ip": ip,
                        "first_seen": now,
                        "last_seen": now,
                        "status": "trusted" if mac in local_whitelist else "rogue"
                    }
                    # report to backend and create alert if not whitelisted
                    backend_obj = report_device_to_backend(mac, ip)
                    if mac not in local_whitelist:
                        device_id = backend_obj.get("_id") if backend_obj and isinstance(backend_obj, dict) else None
                        create_alert_on_backend(device_id=device_id, mac=mac, alert_type="unauthorized",
                                               description=f"Unauthorized device detected (ARP): {mac} {ip}")
                        # optional: notify backend for quarantine workflow
                        request_quarantine_on_backend(device_id=device_id, mac=mac)
    except Exception as e:
        logging.error("handle_arp error: %s", e)

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
            with scanner_lock:
                if mac in devices:
                    devices[mac]["ip"] = ip or devices[mac].get("ip")
                    devices[mac]["last_seen"] = now
                else:
                    devices[mac] = {
                        "mac": mac,
                        "ip": ip,
                        "first_seen": now,
                        "last_seen": now,
                        "status": "trusted" if mac in local_whitelist else "rogue"
                    }
                    backend_obj = report_device_to_backend(mac, ip)
                    if mac not in local_whitelist:
                        device_id = backend_obj.get("_id") if backend_obj and isinstance(backend_obj, dict) else None
                        create_alert_on_backend(device_id=device_id, mac=mac, alert_type="unauthorized",
                                               description=f"Unauthorized device detected (DHCP): {mac} {ip}")
                        request_quarantine_on_backend(device_id=device_id, mac=mac)
    except Exception as e:
        logging.error("handle_dhcp error: %s", e)

def pkt_handler(pkt):
    try:
        if ARP in pkt:
            handle_arp(pkt)
        elif DHCP in pkt or (pkt.haslayer(UDP) and (pkt[UDP].sport in (67,68) or pkt[UDP].dport in (67,68))):
            handle_dhcp(pkt)
    except Exception as e:
        logging.error("pkt_handler error: %s", e)

# ---- Sniffing thread ----
def sniff_loop(iface=None):
    logging.info("Sniffer thread started (iface=%s)", iface or "auto")
    stop_sniff_flag.clear()
    sniff_kwargs = {"prn": pkt_handler, "store": False, "stop_filter": lambda x: stop_sniff_flag.is_set()}
    if iface:
        sniff_kwargs["iface"] = iface
    try:
        sniff(**sniff_kwargs)
    except Exception as e:
        logging.error("sniff exception: %s", e)
    logging.info("Sniffer thread exiting")

def start_scanner(iface=None):
    global scanner_thread, sniff_iface
    if scanner_thread and scanner_thread.is_alive():
        return False, "scanner already running"
    sniff_iface = iface or sniff_iface
    scanner_thread = threading.Thread(target=sniff_loop, args=(sniff_iface,), daemon=True)
    scanner_thread.start()
    return True, "scanner started"

def stop_scanner():
    if not scanner_thread or not scanner_thread.is_alive():
        return False, "scanner not running"
    stop_sniff_flag.set()
    scanner_thread.join(timeout=5)
    return True, "scanner stopped"

# ---- Active ARP sweep (optional) ----
def active_arp_sweep(iface=None, ip_range=None, timeout=2):
    """Perform a one-shot ARP ping sweep across ip_range.
    ip_range example: "192.168.1.0/24" (requires scapy srp)
    Not used by default, but available via /scan_once.
    """
    from scapy.all import ARP, Ether, srp
    iface = iface or sniff_iface
    if not ip_range:
        return {"error": "ip_range required"}
    try:
        logging.info("Running active ARP sweep on %s %s", iface, ip_range)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
        ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=0)
        found = []
        for _, r in ans:
            mac = r[Ether].src.lower()
            ip = r[ARP].psrc
            found.append({"mac": mac, "ip": ip})
            # update devices map (no duplicate reporting)
            with scanner_lock:
                now = time.time()
                if mac in devices:
                    devices[mac]["ip"] = ip or devices[mac].get("ip")
                    devices[mac]["last_seen"] = now
                else:
                    devices[mac] = {"mac": mac, "ip": ip, "first_seen": now, "last_seen": now,
                                    "status": "trusted" if mac in local_whitelist else "rogue"}
                    report_device_to_backend(mac, ip)
        return {"ok": True, "found": found}
    except Exception as e:
        logging.error("active_arp_sweep error: %s", e)
        return {"error": str(e)}

# ---- Quarantine action (simulated / optional) ----
def attempt_quarantine(mac):
    """
    Simulated quarantine:
      - mark local device entry as 'quarantined'
      - create an alert on backend
    If you want active blocking (deauth), you'd need monitor mode + packet injection and caution.
    """
    mac = mac.lower()
    with scanner_lock:
        if mac not in devices:
            return False, "unknown mac"
        devices[mac]["status"] = "quarantined"
        devices[mac]["quarantined_at"] = time.time()
    # record to backend
    backend_device = report_device_to_backend(mac, devices[mac].get("ip"))
    create_alert_on_backend(device_id=(backend_device.get("_id") if backend_device else None),
                           mac=mac, alert_type="quarantine",
                           description=f"Quarantine applied by scanner service for {mac}")
    return True, "quarantine applied (simulated)"

# ---- Flask routes ----
@app.route("/status", methods=["GET"])
@require_token
def status():
    return jsonify({
        "running": bool(scanner_thread and scanner_thread.is_alive()),
        "interface": sniff_iface,
        "device_count": len(devices),
        "whitelist_count": len(local_whitelist)
    })

@app.route("/start", methods=["POST"])
@require_token
def api_start():
    data = request.get_json(silent=True) or {}
    iface = data.get("iface") or request.args.get("iface")
    ok, msg = start_scanner(iface)
    return jsonify({"ok": ok, "message": msg})

@app.route("/stop", methods=["POST"])
@require_token
def api_stop():
    ok, msg = stop_scanner()
    return jsonify({"ok": ok, "message": msg})

@app.route("/devices", methods=["GET"])
@require_token
def api_devices():
    with scanner_lock:
        # return devices sorted by last_seen desc
        out = sorted(devices.values(), key=lambda x: x.get("last_seen", 0), reverse=True)
        return jsonify(out)

@app.route("/scan_once", methods=["POST"])
@require_token
def api_scan_once():
    data = request.get_json(silent=True) or {}
    ip_range = data.get("ip_range")
    iface = data.get("iface") or sniff_iface
    if not ip_range:
        return jsonify({"error": "ip_range required"}), 400
    res = active_arp_sweep(iface=iface, ip_range=ip_range)
    return jsonify(res)

@app.route("/whitelist", methods=["GET", "POST"])
@require_token
def api_whitelist():
    if request.method == "GET":
        return jsonify(sorted(list(local_whitelist)))
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        mac = (data.get("mac") or "").strip().lower()
        if not mac:
            return jsonify({"error": "mac required"}), 400
        local_whitelist.add(mac)
        save_local_whitelist()
        # If device exists, update status
        with scanner_lock:
            if mac in devices:
                devices[mac]["status"] = "trusted"
        return jsonify({"ok": True, "mac": mac})

@app.route("/whitelist/<path:mac>", methods=["DELETE"])
@require_token
def api_whitelist_delete(mac):
    mac = mac.strip().lower()
    if mac in local_whitelist:
        local_whitelist.remove(mac)
        save_local_whitelist()
        with scanner_lock:
            if mac in devices:
                devices[mac]["status"] = "rogue"
        return jsonify({"ok": True, "mac": mac})
    return jsonify({"error": "not found"}), 404

@app.route("/quarantine", methods=["POST"])
@require_token
def api_quarantine():
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    ok, msg = attempt_quarantine(mac)
    return jsonify({"ok": ok, "message": msg})

@app.route("/unquarantine", methods=["POST"])
@require_token
def api_unquarantine():
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    with scanner_lock:
        if mac in devices:
            devices[mac]["status"] = "trusted"
    return jsonify({"ok": True, "message": f"{mac} released"})


# ---- Graceful shutdown handling ----
def shutdown_signal_handler(signum, frame):
    logging.info("Received shutdown signal, stopping scanner")
    stop_sniff_flag.set()
    time.sleep(0.5)
    try:
        func = request.environ.get('werkzeug.server.shutdown')
        if func:
            func()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_signal_handler)
signal.signal(signal.SIGTERM, shutdown_signal_handler)

# ---- Init whitelist & optionally auto-start scanner ----
local_whitelist = load_local_whitelist()
logging.info("Local whitelist loaded (%d entries)", len(local_whitelist))

if __name__ == "__main__":
    # Auto-start if configured
    auto_start = os.getenv("SCANNER_AUTO_START", "true").lower() in ("1", "true", "yes")
    if auto_start:
        ok, msg = start_scanner(SCAN_INTERFACE or None)
        logging.info("Auto-start scanner: %s %s", ok, msg)
    # Run Flask
    logging.info("Launching scanner service API on port %s", SERVICE_PORT)
    # Flask only for local control; ensure firewall/ACLs protect this port
    app.run(host="0.0.0.0", port=SERVICE_PORT)
