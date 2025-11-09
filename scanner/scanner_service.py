#!/usr/bin/env python3
"""
scanner_service.py  —  Demo-ready version

- Runs passive ARP/DHCP scanner
- Reports devices + alerts to backend
- Provides local REST API for control
- Quarantines devices using Windows Firewall (PowerShell)
"""

import os
import time
import logging
import sys
import threading
import signal
import json
import socket
import subprocess
from functools import wraps
from dotenv import load_dotenv
from scapy.all import sniff, ARP, BOOTP, DHCP, UDP, send
import requests
from flask import Flask, request, jsonify, abort
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ---- Load config ----
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000/api")
SCAN_INTERFACE = os.getenv("SCAN_INTERFACE", "").strip() or None 
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "whitelist.txt")
LOG_FILE = os.getenv("LOG_FILE", "scanner_service.log")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "3"))
SERVICE_PORT = int(os.getenv("SCANNER_SERVICE_PORT", "9000"))
API_AUTH_TOKEN = os.getenv("SCANNER_API_TOKEN", "supersecret_scanner_token")

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)

# ---- Flask app ----
app = Flask(__name__)

# ---- Global state ----
devices = {}
last_seen_times = {}
local_whitelist = set()
scanner_thread = None
stop_sniff_flag = threading.Event()
scanner_lock = threading.Lock()
sniff_iface = SCAN_INTERFACE or None

# ---- Auth decorator ----
def require_token(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = None
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

# ---- Helper utilities ----
def get_default_gateway():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

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
        "status": "trusted" if mac.lower() in local_whitelist else "rogue",
    }
    try:
        r = requests.post(f"{BACKEND_URL}/devices", json=payload, timeout=5)
        if r.status_code in (200, 201):
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
        if r.status_code in (200, 201):
            logging.info("Created alert on backend for %s", mac or device_id)
            return r.json()
    except Exception as e:
        logging.error("Error creating alert on backend: %s", e)
    return None

# ---- Packet handlers ----
def handle_arp(pkt):
    try:
        if ARP in pkt and pkt[ARP].op in (1, 2):
            mac = pkt[ARP].hwsrc.lower()
            ip = pkt[ARP].psrc
            if not should_process(mac):
                return
            now = time.time()
            with scanner_lock:
                devices[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "first_seen": devices.get(mac, {}).get("first_seen", now),
                    "last_seen": now,
                    "status": "trusted" if mac in local_whitelist else "rogue",
                }
            backend_obj = report_device_to_backend(mac, ip)
            if mac not in local_whitelist:
                device_id = backend_obj.get("_id") if backend_obj else None
                create_alert_on_backend(
                    device_id=device_id,
                    mac=mac,
                    alert_type="unauthorized",
                    description=f"Unauthorized device detected: {mac} ({ip})",
                )
    except Exception as e:
        logging.error("handle_arp error: %s", e)

def handle_dhcp(pkt):
    try:
        if BOOTP in pkt:
            chaddr = pkt[BOOTP].chaddr
            mac = ":".join(f"{b:02x}" for b in chaddr[:6]).lower()
            ip = pkt[BOOTP].yiaddr
            if not should_process(mac):
                return
            now = time.time()
            with scanner_lock:
                devices[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "first_seen": devices.get(mac, {}).get("first_seen", now),
                    "last_seen": now,
                    "status": "trusted" if mac in local_whitelist else "rogue",
                }
            backend_obj = report_device_to_backend(mac, ip)
            if mac not in local_whitelist:
                device_id = backend_obj.get("_id") if backend_obj else None
                create_alert_on_backend(
                    device_id=device_id,
                    mac=mac,
                    alert_type="unauthorized",
                    description=f"Unauthorized device detected: {mac} ({ip})",
                )
    except Exception as e:
        logging.error("handle_dhcp error: %s", e)

def pkt_handler(pkt):
    try:
        if ARP in pkt:
            handle_arp(pkt)
        elif DHCP in pkt or (pkt.haslayer(UDP) and (pkt[UDP].sport in (67, 68))):
            handle_dhcp(pkt)
    except Exception as e:
        logging.error("pkt_handler error: %s", e)

# ---- Sniffer ----
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
        return False, "already running"
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

# ---- Flask Routes ----
@app.route("/status", methods=["GET"])
@require_token
def api_status():
    return jsonify({
        "running": bool(scanner_thread and scanner_thread.is_alive()),
        "interface": sniff_iface,
        "device_count": len(devices),
        "whitelist_count": len(local_whitelist),
    })

@app.route("/devices", methods=["GET"])
@require_token
def api_devices():
    with scanner_lock:
        return jsonify(sorted(devices.values(), key=lambda x: x["last_seen"], reverse=True))

@app.route("/whitelist", methods=["GET", "POST"])
@require_token
def api_whitelist():
    if request.method == "GET":
        return jsonify(sorted(list(local_whitelist)))
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    local_whitelist.add(mac)
    save_local_whitelist()
    with scanner_lock:
        if mac in devices:
            devices[mac]["status"] = "trusted"
    return jsonify({"ok": True, "mac": mac})

# ---- Windows Firewall Quarantine ----
@app.route("/quarantine", methods=["POST"])
@require_token
def api_quarantine():
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400

    try:
        cmd = [
            "powershell",
            "-Command",
            f'New-NetFirewallRule -DisplayName "Quarantine-{ip}" '
            f'-Direction Outbound -RemoteAddress {ip} -Action Block'
        ]
        subprocess.run(cmd, check=True)
        logging.info(f"✅ Quarantined {mac or ip} using Windows Firewall")

        with scanner_lock:
            if mac in devices:
                devices[mac]["status"] = "quarantined"
        create_alert_on_backend(mac=mac, alert_type="quarantine", description=f"Firewall blocked {ip}")

        return jsonify({"ok": True, "message": f"Device {ip} quarantined"}), 200

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to quarantine {ip}: {e}")
        return jsonify({"error": "Firewall rule failed"}), 500
    

@app.route("/release", methods=["POST"])
@require_token
def api_release():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400

    try:
        # 🔥 Force remove all firewall rules that reference this IP (even multiple entries)
        cmd = [
            "powershell",
            "-Command",
            (
                f'$rules = Get-NetFirewallRule | Where-Object {{$_.DisplayName -like "*Quarantine-{ip}*"}}; '
                f'if ($rules) {{ $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue; '
                f'Write-Host "Removed quarantine rules for {ip}" }} '
                f'else {{ Write-Host "No quarantine rules found for {ip}" }}'
            )
        ]

        subprocess.run(cmd, check=True, shell=True)

        # 🧹 Flush ARP cache for the IP
        subprocess.run(["arp", "-d", ip], shell=True)

        logging.info(f"✅ Released {ip} from quarantine (rules removed & ARP flushed)")

        # Update internal state
        with scanner_lock:
            for mac, dev in devices.items():
                if dev.get("ip") == ip:
                    dev["status"] = "trusted"
                    break

        create_alert_on_backend(mac=None, alert_type="release", description=f"Firewall unblocked {ip}")
        return jsonify({"ok": True, "message": f"Device {ip} released"}), 200

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to release {ip}: {e}")
        return jsonify({"error": "Unblock failed"}), 500


# ---- Startup ----
def shutdown_signal_handler(signum, frame):
    logging.info("Received shutdown signal, stopping scanner")
    stop_sniff_flag.set()
    time.sleep(0.5)
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_signal_handler)
signal.signal(signal.SIGTERM, shutdown_signal_handler)

local_whitelist = load_local_whitelist()
logging.info("Local whitelist loaded (%d entries)", len(local_whitelist))


# ---- Frontend-triggered endpoints (proxy to local quarantine/release) ----
@app.route("/devices/quarantine/<device_id>", methods=["PUT"])
def quarantine_device(device_id):
    device = next((d for d in devices.values() if str(d.get("_id")) == str(device_id)), None)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    ip = device.get("ip")
    mac = device.get("mac")
    if not ip:
        return jsonify({"error": "Device IP missing"}), 400

    try:
        res = requests.post(
            "http://127.0.0.1:9000/quarantine",
            headers={"Authorization": f"Bearer {API_AUTH_TOKEN}"},
            json={"ip": ip, "mac": mac},
            timeout=5
        )
        logging.info(f"Forwarded quarantine request for {ip}")
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logging.error(f"Failed to forward quarantine request: {e}")
        return jsonify({"error": "Internal proxy error"}), 500


@app.route("/devices/release/<device_id>", methods=["PUT"])
def release_device(device_id):
    device = next((d for d in devices.values() if str(d.get("_id")) == str(device_id)), None)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    ip = device.get("ip")
    if not ip:
        return jsonify({"error": "Device IP missing"}), 400

    try:
        res = requests.post(
            "http://127.0.0.1:9000/release",
            headers={"Authorization": f"Bearer {API_AUTH_TOKEN}"},
            json={"ip": ip},
            timeout=5
        )
        logging.info(f"Forwarded release request for {ip}")
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logging.error(f"Failed to forward release request: {e}")
        return jsonify({"error": "Internal proxy error"}), 500

if __name__ == "__main__":
    auto_start = True
    if auto_start:
        ok, msg = start_scanner(SCAN_INTERFACE or None)
        logging.info("Auto-start scanner: %s %s", ok, msg)
    logging.info("Launching scanner service API on port %s", SERVICE_PORT)
    app.run(host="0.0.0.0", port=SERVICE_PORT)
