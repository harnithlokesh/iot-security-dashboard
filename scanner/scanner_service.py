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
import hashlib
from functools import wraps
from dotenv import load_dotenv
from scapy.all import sniff, ARP, BOOTP, DHCP, UDP, send
from scapy.all import get_if_list, get_if_addr

import requests
from flask import Flask, request, jsonify, abort
import io
import netifaces
import psutil

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ---- Load config ----
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000/api")
SCAN_INTERFACE = os.getenv("SCAN_INTERFACE")
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "whitelist.txt")
LOG_FILE = os.getenv("LOG_FILE", "scanner_service.log")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "5"))
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
network_monitor_thread = None
stop_monitor_flag = threading.Event()
last_network_signature = None

STALE_DEVICE_INTERVAL = 300

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
        "mac": mac.lower(),
        "ip": ip or "",
        "status": "trusted" if mac.lower() in local_whitelist else "rogue",
        "router_ip": get_default_gateway(),  # optional, helps backend identify network
        "network_signature": last_network_signature # new
    }
    try:
        r = requests.post(f"{BACKEND_URL}/devices", json=payload, timeout=5)
        if r.status_code in (200, 201):
            logging.info("Reported device to backend: %s %s", mac, ip)
            return r.json()
        elif r.status_code == 409:
            # duplicate, try update
            r2 = requests.put(f"{BACKEND_URL}/devices/{mac}", json=payload, timeout=5)
            return r2.json() if r2.status_code in (200, 201) else None
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

# ----------------------------
# Helper: network signature
# ----------------------------
def get_network_signature():
    scapy_if, gateway, local_ip, friendly = detect_active_interface()
    text = f"{scapy_if or ''}-{gateway or ''}-{local_ip or ''}"
    return hashlib.md5(text.encode()).hexdigest()

def reset_devices_for_new_network(new_signature):
    """Clear all devices when network changes."""
    global devices, last_seen_times, last_network_signature
    with scanner_lock:
        devices.clear()
        last_seen_times.clear()
        last_network_signature = new_signature
    logging.info("🔄 Devices reset due to network change")
    # Notify backend to refresh scan (optional)
    try:
        requests.post(f"{BACKEND_URL}/devices/refresh-scan", json={"network_signature": new_signature}, timeout=3)
        requests.post(f"{BACKEND_URL}/events/network-changed", json={"message": "network_changed"}, timeout=3)
    except Exception:
        pass

# ----------------------------
# Stale device cleanup
# ----------------------------
def cleanup_stale_devices():
    while True:
        now = time.time()
        with scanner_lock:
            stale_macs = [mac for mac, d in devices.items() if now - d["last_seen"] > STALE_DEVICE_INTERVAL]
            for mac in stale_macs:
                del devices[mac]
        time.sleep(STALE_DEVICE_INTERVAL // 2)

threading.Thread(target=cleanup_stale_devices, daemon=True).start()

# ---- Packet handlers ----
def handle_arp(pkt):
    try:
        global last_network_signature
        # Check network signature
        current_sig = get_network_signature()
        if last_network_signature != current_sig:
            reset_devices_for_new_network(current_sig)

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
            if mac not in local_whitelist and backend_obj:
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
        global last_network_signature
        current_sig = get_network_signature()
        if last_network_signature != current_sig:
            reset_devices_for_new_network(current_sig)

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
        try:
            sniff_kwargs["iface"] = iface
        except Exception as e:
            logging.warning("Failed to set iface param for sniff: %s", e)
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
    global scanner_thread
    if not scanner_thread or not scanner_thread.is_alive():
        return False, "scanner not running"
    stop_sniff_flag.set()
    scanner_thread.join(timeout=5)
    scanner_thread = None
    return True, "scanner stopped"


# ---- Network detection ----
def detect_active_interface():
    """
    Returns (scapy_iface_name, gateway_ip, local_ip, iface_friendly_name)
    """
    try:
        gw = netifaces.gateways()
        default = gw.get('default', {})
        if netifaces.AF_INET in default:
            gateway_ip, iface_name = default[netifaces.AF_INET]
        else:
            # fallback: pick interface with a non-loopback IP
            iface_name = None
            gateway_ip = None
            for ifname in netifaces.interfaces():
                addrs = netifaces.ifaddresses(ifname).get(netifaces.AF_INET)
                if addrs:
                    for a in addrs:
                        ip = a.get('addr')
                        if ip and not ip.startswith("127."):
                            iface_name = ifname
                            break
                if iface_name:
                    break
        local_ip = None
        try:
            local_ip = get_if_addr(iface_name)
        except Exception:
            # fallback via netifaces
            try:
                addrs = netifaces.ifaddresses(iface_name).get(netifaces.AF_INET)
                if addrs:
                    local_ip = addrs[0].get('addr')
            except Exception:
                local_ip = None

        # Map to scapy interface list: sometimes scapy lists NPF names on Windows,
        # otherwise the ifname itself should work.
        scapy_if = None
        for s in get_if_list():
            # match exact or substring (covers Windows device strings)
            if iface_name and (s == iface_name or iface_name in s or s in iface_name):
                scapy_if = s
                break
        scapy_if = scapy_if or iface_name

        return scapy_if, gateway_ip, local_ip, iface_name
    except Exception as e:
        logging.error("detect_active_interface error: %s", e)
        return None, None, None, None

def get_public_isp():
    try:
        r = requests.get("https://ipinfo.io/json", timeout=2)
        j = r.json()
        return j.get("org") or j.get("asn") or j.get("city") or "Unknown", j.get("ip")
    except Exception:
        return "Unknown", None

def signature_for(interface, gateway, local_ip):
    text = f"{interface or ''}-{gateway or ''}-{local_ip or ''}"
    return hashlib.md5(text.encode()).hexdigest()

def reset_scanner_state():
    global devices, last_seen_times, local_whitelist
    with scanner_lock:
        devices = {}
        last_seen_times = {}
    # Ask backend to reset stored devices (best-effort)
    try:
        requests.post(f"{BACKEND_URL}/devices/refresh-scan", json={"network_signature": last_network_signature}, timeout=3)

    except Exception as e:
        logging.warning("Backend devices reset call failed: %s", e)
    # Create a backend event so frontend can show toast (best-effort)
    try:
        requests.post(f"{BACKEND_URL}/events/network-changed", json={"message": "network_changed"}, timeout=3)
    except Exception:
        pass

# ----------------------------
# Network monitor loop
# ----------------------------
def monitor_network_loop(poll_interval=5):
    logging.info("Network monitor thread started")
    stop_monitor_flag.clear()
    while not stop_monitor_flag.is_set():
        try:
            current_sig = get_network_signature()
            if last_network_signature != current_sig:
                logging.info("Network signature changed -> resetting scanner")
                stop_scanner()
                reset_devices_for_new_network(current_sig)
                scapy_if, _, _, _ = detect_active_interface()
                start_scanner(scapy_if)
        except Exception as e:
            logging.error("monitor_network_loop error: %s", e)
        stop_monitor_flag.wait(poll_interval)
    logging.info("Network monitor thread exiting")


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

@app.route("/interfaces", methods=["GET"])
@require_token
def api_interfaces():
    scapy_if, gateway, local_ip, friendly = detect_active_interface()
    isp, public_ip = get_public_isp()
    iface_list = []
    for s in get_if_list():
        try:
            ip = get_if_addr(s)
        except Exception:
            ip = None
        iface_list.append({
            "name": s,
            "npf_name": s,
            "ip": ip,
            "isp": isp,
        })
    # also include the detected default interface first for convenience
    default_obj = {"name": friendly or scapy_if or "default", "npf_name": scapy_if, "ip": local_ip, "isp": isp}
    # ensure default appears at top and no duplicates
    iface_unique = [default_obj] + [i for i in iface_list if i["npf_name"] != default_obj["npf_name"]]
    return jsonify(iface_unique)

@app.route("/network-signature", methods=["GET"])
@require_token
def api_network_signature():
    scapy_if, gateway, local_ip, friendly = detect_active_interface()
    isp, public_ip = get_public_isp()
    return jsonify({
        "interface": friendly or scapy_if,
        "npf": scapy_if,
        "gateway": gateway,
        "local_ip": local_ip,
        "public_ip": public_ip,
        "isp": isp
    })

@app.route("/start", methods=["POST"])
@require_token
def start_scan():
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    ok, msg = start_scanner(iface)
    return jsonify({"ok": ok, "message": msg, "interface": iface})

@app.route("/stop", methods=["POST"])
@require_token
def stop_scan_api():
    ok, msg = stop_scanner()
    return jsonify({"ok": ok, "message": msg})

@app.route("/reset", methods=["POST"])
@require_token
def api_reset():
    # clear local state, ask backend to clear, and restart scanner on detected interface
    reset_scanner_state()
    scapy_if, gateway, local_ip, friendly = detect_active_interface()
    ok, msg = start_scanner(scapy_if)
    return jsonify({"ok": True, "message": "reset and restarted", "interface": scapy_if})


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
        #  Force remove all firewall rules that reference this IP (even multiple entries)
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

        #  Flush ARP cache for the IP
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
        with scanner_lock:
            device["status"] = "trusted"
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
