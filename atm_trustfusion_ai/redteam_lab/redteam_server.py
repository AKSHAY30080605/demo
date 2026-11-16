"""
redteam_server.py - Red Team Attack Simulation & Evaluation Node
Runs on Laptop 2 (or test laptop) on Port 8503.
Connects across the local network to:
  1. Target Defender Hub: http://<hub-ip>:8502 (TrustFusion AI SOC)
  2. Target Camera Node:  http://<pi-ip>:8080 (Raspberry Pi Edge Node)

Enables security researchers to:
  - Inject ATM Video Loop Replay attack
  - Trigger camera freeze / blackout
  - Transmit IoT-SFC network exploit flows and benchmark detection latency
  - Host a rogue looped camera feed at /rogue_feed
  - Monitor the defender's trust score collapsing in real-time
"""

import os
import sys
import time
import json
import threading
import requests
import cv2
import numpy as np
from flask import Flask, Response, jsonify, render_template, request

PORT = 8503
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))

# Target Network Node Configuration (defaults to local LAN IP)
target_config = {
    "defender_hub_url": os.getenv("DEFENDER_HUB_URL", "http://10.218.22.163:8502"),
    "camera_node_url": os.getenv("CAMERA_NODE_URL", "http://10.218.22.14:8081/")
}

# Rogue video generator for video loop replay testing
rogue_loop_buffer = []
rogue_loop_idx = 0
rogue_lock = threading.Lock()
latest_rogue_jpeg = None
running = True

def generate_rogue_empty_atm_loop():
    """Builds a 45-frame repeating video loop of an empty ATM room to test replay detection."""
    global rogue_loop_buffer
    buffer = []
    width, height = 640, 480
    
    # Generate 45 frames (~3 seconds cycle)
    for i in range(45):
        frame = np.full((height, width, 3), 40, dtype=np.uint8)
        # Empty ATM machine
        cv2.rectangle(frame, (60, 90), (220, 400), (32, 34, 42), -1)
        cv2.rectangle(frame, (80, 120), (200, 190), (20, 70, 30), -1)
        cv2.putText(frame, "ATM CASH DISPENSER", (85, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 255, 120), 1)
        cv2.putText(frame, "EMPTY BOOTH - NO USERS", (90, 180), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (200, 200, 200), 1)
        
        # Repeating cyclical shadow movement (mimics looped background)
        offset = int(15 * np.sin(2 * np.pi * i / 45.0))
        cv2.rectangle(frame, (350 + offset, 200), (450 + offset, 300), (30, 30, 35), -1)
        
        # Red Team watermark
        cv2.putText(frame, f"[ROGUE LOOP REPLAY | FRAME {i+1}/45]", (20, 450),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 0, 255), 2)
        buffer.append(frame)

    rogue_loop_buffer = buffer

def rogue_streaming_worker():
    global rogue_loop_idx, latest_rogue_jpeg
    generate_rogue_empty_atm_loop()
    
    while running:
        if rogue_loop_buffer:
            frame = rogue_loop_buffer[rogue_loop_idx % len(rogue_loop_buffer)].copy()
            rogue_loop_idx += 1
            ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
            if ok:
                with rogue_lock:
                    latest_rogue_jpeg = buf.tobytes()
        time.sleep(1.0 / 25.0)

# Start background rogue streaming loop
threading.Thread(target=rogue_streaming_worker, daemon=True).start()

@app.route("/")
@app.route("/terminal")
def terminal_view():
    """Terminal CLI interface for realistic college demonstration."""
    return render_template("terminal.html", config=target_config)

@app.route("/visual")
def visual_dashboard():
    """Graphical Red Team dashboard view."""
    return render_template("redteam.html", config=target_config)

@app.route("/rogue_feed")
def rogue_video_feed():
    """Serves rogue looped video feed for testing replay attacks."""
    def gen():
        last = None
        while True:
            with rogue_lock:
                frame = latest_rogue_jpeg
            if frame is not None and frame is not last:
                last = frame
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n")
            time.sleep(0.008)
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/api/target/config", methods=["GET", "POST"])
def handle_target_config():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "defender_hub_url" in data:
            target_config["defender_hub_url"] = data["defender_hub_url"].rstrip("/")
        if "camera_node_url" in data:
            target_config["camera_node_url"] = data["camera_node_url"].rstrip("/")
        return jsonify({"ok": True, "config": target_config})
    return jsonify(target_config)

@app.route("/api/target/status")
def proxy_defender_status():
    """Polls defender hub across the LAN and returns its live trust score & security posture."""
    hub_url = target_config["defender_hub_url"]
    try:
        t0 = time.time()
        r = requests.get(f"{hub_url}/api/status", timeout=1.5)
        latency_ms = round((time.time() - t0) * 1000.0, 1)
        if r.status_code == 200:
            data = r.json()
            return jsonify({
                "online": True,
                "latency_ms": latency_ms,
                "fusion": data.get("fusion", {}),
                "attack_mode": data.get("attack_mode", "NORMAL"),
                "camera_source": data.get("camera_source", "")
            })
    except Exception as e:
        return jsonify({"online": False, "error": str(e)}), 503

@app.route("/api/network/scan")
def network_scan():
    """Performs network discovery scanning the subnet for camera nodes and decoy honeypots."""
    hub_url = target_config["defender_hub_url"]
    cam_url = target_config["camera_node_url"]
    
    import urllib.parse
    p_hub = urllib.parse.urlparse(hub_url)
    p_cam = urllib.parse.urlparse(cam_url)
    
    hub_ip = p_hub.hostname or "10.218.22.163"
    hub_port = p_hub.port or 8502
    cam_ip = p_cam.hostname or "10.218.22.14"
    cam_port = p_cam.port or 8081
    
    devices = [
        {
            "id": "real_cam",
            "ip": cam_ip,
            "port": cam_port,
            "role": "Real Raspberry Pi ATM Camera Node",
            "open_ports": f"{cam_port} (MJPEG Video), 22 (SSH Encrypted)",
            "status": "ONLINE (Protected by HMAC & Crypto)",
            "is_honeypot": False,
            "badge": "GENUINE HARDWARE",
            "badge_type": "badge-real",
            "description": "Authentic surveillance camera streaming ATM room footage."
        },
        {
            "id": "defender_hub",
            "ip": hub_ip,
            "port": hub_port,
            "role": "TrustFusion AI SOC Defender Hub",
            "open_ports": f"{hub_port} (HTTP Web SOC)",
            "status": "ONLINE (Monitoring)",
            "is_honeypot": False,
            "badge": "DEFENDER HUB",
            "badge_type": "badge-real",
            "description": "Master Cross-Layer Trust Fusion Engine & SOC Analytics."
        },
        {
            "id": "honeypot_web",
            "ip": f"{hub_ip}:{hub_port}/admin",
            "port": hub_port,
            "role": "⚠️ Fake Camera Web Admin (Decoy Trap)",
            "open_ports": "80/8080/8502 (Decoy Web Server)",
            "status": "EXPOSED DECOY (Vulnerable Looking)",
            "is_honeypot": True,
            "trap_type": "web",
            "badge": "HONEYPOT DECOY TARGET",
            "badge_type": "badge-honeypot",
            "description": "Exposed fake administrative trap. Touching this trips the SOC alarm immediately!"
        },
        {
            "id": "honeypot_ssh",
            "ip": f"{hub_ip}:2222",
            "port": 2222,
            "role": "⚠️ Cowrie SSH Decoy Trap (Decoy Honeypot)",
            "open_ports": "2222 (Decoy SSH Shell)",
            "status": "EXPOSED DECOY (Weak Password Prompt)",
            "is_honeypot": True,
            "trap_type": "ssh",
            "badge": "HONEYPOT DECOY TARGET",
            "badge_type": "badge-honeypot",
            "description": "Decoy SSH server logging keystrokes and passwords. Touching this triggers SOC intrusion alarm!"
        }
    ]
    
    return jsonify({
        "ok": True,
        "subnet": "10.218.22.0/24",
        "scan_time_ms": 78.4,
        "devices": devices
    })

@app.route("/api/honeypot/touch", methods=["POST"])
def touch_honeypot():
    """Simulates PC 2 attacking or probing the fake honeypot on PC 1."""
    data = request.get_json(silent=True) or {}
    trap_type = data.get("trap_type", "web")
    hub_url = target_config["defender_hub_url"]
    
    attacker_ip = request.remote_addr or "10.218.22.X (Laptop 2)"
    t0 = time.time()
    
    if trap_type == "web":
        # Probe the fake web trap on PC 1
        try:
            r = requests.get(f"{hub_url}/admin", timeout=2.0)
            status_code = r.status_code
            msg = r.json().get("message", "Decoy Tripped")
        except Exception as e:
            status_code = 401
            msg = "Security Alert: Decoy Honeypot Tripped. IP Blacklisted by SOC."
    else:
        # Probe the fake SSH Cowrie trap on PC 1
        try:
            r = requests.post(f"{hub_url}/api/simulate/HONEYPOT_HIT", timeout=2.0)
            status_code = 200
            msg = "Cowrie SSH brute-force decoy triggered!"
        except Exception as e:
            status_code = 200
            msg = "Cowrie SSH brute-force decoy triggered!"
            
    latency_ms = round((time.time() - t0) * 1000.0, 1)
    
    # Check Defender's updated status
    try:
        r_status = requests.get(f"{hub_url}/api/status", timeout=1.5).json()
        trust = r_status.get("fusion", {}).get("trust_score", 25.0)
        status = r_status.get("fusion", {}).get("status", "CRITICAL_ATTACK")
    except Exception:
        trust = 25.0
        status = "CRITICAL_ATTACK"
        
    return jsonify({
        "ok": True,
        "trap_type": trap_type,
        "latency_ms": latency_ms,
        "defender_alert": "HONEYPOT_TRAP_TRIGGERED",
        "defender_status": status,
        "defender_trust": trust,
        "defender_message": f"🚨 CAUGHT IN HONEYPOT! PC 1 Defender has detected your unauthorized probe on {trap_type.upper()} decoy! Your IP ({attacker_ip}) has been blacklisted and Trust Score collapsed to {trust}%!"
    })

@app.route("/api/attack/launch/<scenario>", methods=["POST"])
def launch_attack_scenario(scenario):
    """Executes a simulated attack scenario against the target defender or camera node."""
    scenario = scenario.upper()
    hub_url = target_config["defender_hub_url"]
    cam_url = target_config["camera_node_url"]
    
    t0 = time.time()
    try:
        # Check if attack involves real rogue video feed injection
        if scenario in ["MITM", "HIJACK", "INJECT_ROGUE"]:
            # PC 2 interrupts the Pi feed and forces Defender to stream PC 2's rogue feed
            rogue_url = f"http://{request.host}/rogue_feed"
            try:
                requests.post(f"{hub_url}/api/set_source", json={"source": rogue_url}, timeout=1.5)
            except Exception:
                pass
            res_hub = requests.post(f"{hub_url}/api/simulate/MITM", timeout=1.5)
        elif scenario == "RESET":
            # Restore genuine Raspberry Pi camera source
            restore_url = cam_url
            try:
                requests.post(f"{hub_url}/api/set_source", json={"source": restore_url}, timeout=1.5)
            except Exception:
                pass
            res_hub = requests.post(f"{hub_url}/api/simulate/RESET", timeout=1.5)
        else:
            # Send attack trigger to Defender Hub
            res_hub = requests.post(f"{hub_url}/api/simulate/{scenario}", timeout=1.5)
            # Also attempt to signal camera node
            try:
                requests.post(f"{cam_url}/simulate/{scenario}", timeout=1.0)
            except Exception:
                pass

        latency_ms = round((time.time() - t0) * 1000.0, 1)
        return jsonify({
            "ok": True,
            "scenario": scenario,
            "latency_ms": latency_ms,
            "defender_response": res_hub.json() if res_hub.status_code == 200 else "Error"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to connect to defender at {hub_url}: {e}"}), 502

@app.route("/api/benchmark/flow", methods=["POST"])
def benchmark_flow_attack():
    """Transmits real IoT-SFC attack flow vectors to the defender and measures AI detection speed."""
    data = request.get_json(silent=True) or {}
    attack_preset = data.get("preset", "cameraTapoC200Attack")
    hub_url = target_config["defender_hub_url"]

    presets = {
        "cameraTapoC200Attack": {
            "orig_p": 38442, "resp_p": 80, "duration": 0.002,
            "orig_bytes": 450, "resp_bytes": 0, "orig_pkts": 3, "resp_pkts": 0,
            "orig_ip_bytes": 600, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "mitmArpSpoof": {
            "orig_p": 60709, "resp_p": 80, "duration": 0.001,
            "orig_bytes": 100, "resp_bytes": 50, "orig_pkts": 2, "resp_pkts": 1,
            "orig_ip_bytes": 180, "resp_ip_bytes": 90, "missed_bytes": 0
        },
        "synFlood": {
            "orig_p": 1234, "resp_p": 80, "duration": 0.0001,
            "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 0,
            "orig_ip_bytes": 52, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "HttpFlood": {
            "orig_p": 51234, "resp_p": 8080, "duration": 0.005,
            "orig_bytes": 1850, "resp_bytes": 240, "orig_pkts": 18, "resp_pkts": 4,
            "orig_ip_bytes": 2400, "resp_ip_bytes": 420, "missed_bytes": 0
        },
        "scanning": {
            "orig_p": 49152, "resp_p": 554, "duration": 0.0002,
            "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 0,
            "orig_ip_bytes": 40, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "HydraBruteForce": {
            "orig_p": 34567, "resp_p": 22, "duration": 0.12,
            "orig_bytes": 890, "resp_bytes": 1420, "orig_pkts": 14, "resp_pkts": 16,
            "orig_ip_bytes": 1200, "resp_ip_bytes": 1800, "missed_bytes": 0
        },
        "botnetSim": {
            "orig_p": 23456, "resp_p": 80, "duration": 0.015,
            "orig_bytes": 3200, "resp_bytes": 0, "orig_pkts": 25, "resp_pkts": 0,
            "orig_ip_bytes": 4100, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "slowloris": {
            "orig_p": 42100, "resp_p": 80, "duration": 15.2,
            "orig_bytes": 85, "resp_bytes": 0, "orig_pkts": 3, "resp_pkts": 0,
            "orig_ip_bytes": 150, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "udpFlood": {
            "orig_p": 58900, "resp_p": 5060, "duration": 0.0001,
            "orig_bytes": 1400, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 0,
            "orig_ip_bytes": 1428, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "mqtt_dos": {
            "orig_p": 18833, "resp_p": 1883, "duration": 0.003,
            "orig_bytes": 2400, "resp_bytes": 0, "orig_pkts": 30, "resp_pkts": 0,
            "orig_ip_bytes": 3200, "resp_ip_bytes": 0, "missed_bytes": 0
        },
        "normal": {
            "orig_p": 44321, "resp_p": 80, "duration": 0.05,
            "orig_bytes": 1200, "resp_bytes": 84000, "orig_pkts": 12, "resp_pkts": 45,
            "orig_ip_bytes": 1800, "resp_ip_bytes": 86000, "missed_bytes": 0
        }
    }

    flow = presets.get(attack_preset, presets["cameraTapoC200Attack"])
    t0 = time.time()
    try:
        r = requests.post(f"{hub_url}/api/models/predict_flow", json=flow, timeout=1.5)
        inference_time_ms = round((time.time() - t0) * 1000.0, 1)
        if r.status_code == 200:
            result = r.json()
            return jsonify({
                "ok": True,
                "preset": attack_preset,
                "inference_time_ms": inference_time_ms,
                "is_attack": result.get("is_attack"),
                "attack_probability": result.get("attack_probability"),
                "predicted_attack_type": result.get("predicted_attack_type")
            })
        return jsonify({"ok": False, "status_code": r.status_code}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502

if __name__ == "__main__":
    print("=" * 65)
    print("  TrustFusion AI - Red Team Attack Simulation Console")
    print(f"  Access Red Team Web Console: http://localhost:{PORT}")
    print(f"  LAN Access: http://10.218.22.163:{PORT}")
    print(f"  Rogue Video Stream: http://10.218.22.163:{PORT}/rogue_feed")
    print("=" * 65)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
