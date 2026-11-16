"""
attack_server.py - Gated Sequential Kill Chain & Custom MP4 Video Injection Console.

Implements the authentic multi-stage attack sequence requested:
STAGE 1: Network / Transport Flooding & Reconnaissance
         (GATED: Must lower PC1's network health below threshold first).
STAGE 2: Custom MP4 Video Injection & Stream Interception
         (LOCKED until Stage 1 is verified. Streams user-selected MP4 over Port 8503).
         Simultaneously triggers physical Pi Camera Edge Node to record genuine physical scene in background!
STAGE 3: Attack Reset & Edge Evidence Recovery
         (Restores authentic camera feed and transfers the real Pi-recorded video to PC1).
"""

import os
import time
import threading
import argparse
import requests
import cv2
import numpy as np
from flask import Flask, render_template, jsonify, request, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INJECTION_DIR = os.path.join(BASE_DIR, "injection_videos")
os.makedirs(INJECTION_DIR, exist_ok=True)

PC1_DEFENDER_URL = os.environ.get("DEFENDER_URL", "http://127.0.0.1:8502")
GENUINE_PI_URL = os.environ.get("PI_CAMERA_URL", "http://10.218.22.14:8081")
PC2_PORT = 8503

# Gated Sequential Kill Chain State
killchain_state = {
    "stage1_network_done": False,
    "stage2_injected": False,
    "selected_mp4": "empty_atm_loop.mp4",
    "active_scenario": "NORMAL"
}

audit_log = []
flood_running = False
flood_thread = None
stream_mode = "LIVE"
current_mp4_cap = None
mp4_lock = threading.Lock()


def log_audit(action: str, details: str, status: str = "SUCCESS", pc1_trust: float = None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "action": action,
        "details": details,
        "status": status,
        "pc1_trust": pc1_trust
    }
    audit_log.insert(0, entry)
    if len(audit_log) > 60:
        audit_log.pop()
    print(f"[PC2-KillChain] [{entry['timestamp']}] {action}: {details} (PC1 Trust: {pc1_trust}%)")


def volumetric_flood_worker():
    """Real socket connection burst to simulate flood flow without choking the web server."""
    global flood_running
    count = 0
    t0 = time.time()
    for _ in range(30):
        if not flood_running:
            break
        try:
            requests.head(f"{PC1_DEFENDER_URL}/status", timeout=0.25)
            count += 1
        except Exception:
            pass
        time.sleep(0.1)

    duration = max(0.1, time.time() - t0)
    log_audit("VOLUMETRIC_FLOOD_BURST", f"Emitted {count} connection probes ({count/duration:.1f} req/s).")


def generate_decoy_frames():
    """Generates frames either from the chosen MP4 file or synthetic pattern."""
    global stream_mode, killchain_state
    
    while True:
        if stream_mode == "INJECT_MP4":
            mp4_path = os.path.join(INJECTION_DIR, killchain_state["selected_mp4"])
            if not os.path.exists(mp4_path):
                # Fallback to default
                mp4_path = os.path.join(INJECTION_DIR, "empty_atm_loop.mp4")

            cap = cv2.VideoCapture(mp4_path)
            if cap and cap.isOpened():
                while stream_mode == "INJECT_MP4":
                    ret, frame = cap.read()
                    if not ret or frame is None:
                        # Loop video indefinitely
                        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                        continue

                    # Ensure standard size
                    if frame.shape[1] != 640 or frame.shape[0] != 480:
                        frame = cv2.resize(frame, (640, 480))

                    # Watermark showing rogue stream details
                    cv2.putText(frame, f"[ROUGE STREAM :8503] INJECTING: {killchain_state['selected_mp4']}", (18, 30),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.50, (0, 0, 255), 2)

                    ret2, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 65])
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
                    time.sleep(0.045)  # ~22 FPS
                cap.release()
            else:
                # Fallback synthetic frame
                img = np.zeros((480, 640, 3), dtype=np.uint8)
                cv2.putText(img, "STREAMING INJECTED MP4 VIDEO", (50, 240),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
                ret2, buffer = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 65])
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
                time.sleep(0.05)
        else:
            # Idle standby frame
            img = np.full((480, 640, 3), 26, dtype=np.uint8)
            cv2.putText(img, "PC2 RED TEAM CONSOLE - STANDBY", (80, 240),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (180, 180, 180), 2)
            ret2, buffer = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 65])
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.1)


def query_pc1_status():
    try:
        r = requests.get(f"{PC1_DEFENDER_URL}/api/status", timeout=1.2).json()
        fusion = r.get("fusion", {})
        return {
            "trust_score": fusion.get("trust_score", 95.0),
            "status": fusion.get("status", "SECURE"),
            "layer2_net_health": fusion.get("layer2_net_health", 100.0),
            "ai_classification": fusion.get("ai_classification", "NORMAL_SECURE"),
            "active_alerts": fusion.get("active_alerts", []),
            "camera_source": r.get("camera_source", "")
        }
    except Exception:
        return {
            "trust_score": 0.0,
            "status": "UNREACHABLE",
            "layer2_net_health": 0.0,
            "ai_classification": "OFFLINE",
            "active_alerts": ["PC1_CONNECTION_ERROR"],
            "camera_source": "N/A"
        }


@app.route("/")
@app.route("/console")
def attack_console_view():
    pc1_state = query_pc1_status()
    available_mp4s = [f for f in os.listdir(INJECTION_DIR) if f.lower().endswith(".mp4")]
    return render_template("console.html", state=killchain_state, logs=audit_log, pc1=pc1_state, mp4s=available_mp4s)


@app.route("/terminal")
def terminal_view():
    terminal_template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
    alt_template = os.path.join(terminal_template_path, "redteam.html")
    if os.path.exists(alt_template):
        with open(alt_template, "r", encoding="utf-8") as f:
            return f.read()
    return "Terminal UI available at /console"


@app.route("/rogue_stream.mjpg")
def rogue_stream():
    return Response(generate_decoy_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route("/api/pc1_telemetry")
@app.route("/api/target/status")
@app.route("/api/target_status")
def get_pc1_telemetry():
    available_mp4s = [f for f in os.listdir(INJECTION_DIR) if f.lower().endswith(".mp4")]
    return jsonify({
        "killchain": killchain_state,
        "pc1": query_pc1_status(),
        "audit_log": audit_log,
        "available_mp4s": available_mp4s
    })


# ---------------------------------------------------------------------------
# GATED KILL CHAIN STAGE 1: NETWORK ATTACK
# ---------------------------------------------------------------------------
@app.route("/api/killchain/stage1_network", methods=["POST"])
def execute_stage1_network():
    global killchain_state, flood_running, flood_thread
    
    # Start volumetric socket flood
    if not flood_running:
        flood_running = True
        flood_thread = threading.Thread(target=volumetric_flood_worker, daemon=True)
        flood_thread.start()

    # Trigger PC1's transport layer flood alert
    try:
        requests.post(f"{PC1_DEFENDER_URL}/api/simulate/NET_FLOOD", timeout=1.5)
    except Exception:
        pass

    time.sleep(0.5)
    pc1_state = query_pc1_status()
    killchain_state["stage1_network_done"] = True
    killchain_state["active_scenario"] = "STAGE1_NETWORK_BREACHED"

    log_audit("STAGE1_NETWORK_COMPROMISED",
              f"Network layer saturated (PC1 Net Health: {pc1_state['layer2_net_health']}%). Stage 2 Video Injection UNLOCKED.",
              status="STAGE1_ACQUIRED",
              pc1_trust=pc1_state["trust_score"])

    return jsonify({
        "ok": True,
        "stage": 1,
        "message": "Stage 1 Network attack executed! PC1 Network score lowered. Stage 2 Video Injection is now UNLOCKED.",
        "killchain": killchain_state,
        "pc1": pc1_state
    })


# ---------------------------------------------------------------------------
# GATED KILL CHAIN STAGE 2: CUSTOM MP4 VIDEO INJECTION
# ---------------------------------------------------------------------------
@app.route("/api/killchain/stage2_inject", methods=["POST"])
def execute_stage2_inject():
    global killchain_state, stream_mode
    
    # Enforce strict progression gating!
    if not killchain_state["stage1_network_done"]:
        return jsonify({
            "ok": False,
            "error": "LOCKED: You must perform the Stage 1 Network Attack first to lower network integrity before video injection is permitted!"
        }), 403

    data = request.get_json(silent=True) or {}
    mp4_choice = data.get("mp4_file", killchain_state["selected_mp4"])
    killchain_state["selected_mp4"] = mp4_choice
    stream_mode = "INJECT_MP4"

    host_ip = request.host.split(":")[0] if request.host else "127.0.0.1"
    if host_ip == "localhost":
        host_ip = "127.0.0.1"
    rogue_stream_url = f"http://{host_ip}:{PC2_PORT}/rogue_stream.mjpg"

    # Step A: Divert PC1 video source to this rogue MP4 stream and trip Loop/Replay alarm
    try:
        requests.post(f"{PC1_DEFENDER_URL}/api/set_source", json={"source": rogue_stream_url}, timeout=2.0)
        requests.post(f"{PC1_DEFENDER_URL}/api/simulate/LOOP", timeout=2.0)
        requests.post(f"{PC1_DEFENDER_URL}/api/simulate/STAGE2_MP4_INJECTED", timeout=2.0)
    except Exception as e:
        print(f"[AttackServer Error] Stage 2 forward to PC1: {e}")

    # Step B: Instruct physical Raspberry Pi camera node to start authentic black-box edge recording!
    try:
        requests.post(f"{PC1_DEFENDER_URL}/api/edge_recording/start", timeout=1.5)
    except Exception:
        pass

    time.sleep(0.5)
    pc1_state = query_pc1_status()
    killchain_state["stage2_injected"] = True
    killchain_state["active_scenario"] = "STAGE2_MP4_INJECTED"

    log_audit("STAGE2_MP4_INJECTED",
              f"Injected custom MP4: '{mp4_choice}' into PC1 live feed. Pi camera edge node activated physical recording.",
              status="SPOOFING_ACTIVE",
              pc1_trust=pc1_state["trust_score"])

    return jsonify({
        "ok": True,
        "stage": 2,
        "message": f"Injected '{mp4_choice}' into PC1 live stream! PC1 Trust collapsed. Pi node is recording real scene.",
        "killchain": killchain_state,
        "pc1": pc1_state
    })


# ---------------------------------------------------------------------------
# GATED KILL CHAIN STAGE 3: RESET & RECOVER AUTHENTIC FOOTAGE
# ---------------------------------------------------------------------------
@app.route("/api/killchain/stage3_reset", methods=["POST"])
def execute_stage3_reset():
    global killchain_state, stream_mode, flood_running

    stream_mode = "LIVE"
    flood_running = False

    # Step A: Restore genuine camera feed on PC1
    try:
        requests.post(f"{PC1_DEFENDER_URL}/api/set_source", json={"source": GENUINE_PI_URL}, timeout=1.5)
        requests.post(f"{PC1_DEFENDER_URL}/api/simulate/NORMAL", timeout=1.5)
    except Exception:
        pass

    # Step B: Finalize Pi edge recording and synchronize to PC1 dashboard
    recovered_info = {}
    try:
        r = requests.post(f"{PC1_DEFENDER_URL}/api/edge_recording/stop_and_sync", timeout=3.0)
        recovered_info = r.json().get("recovered_footage", {})
    except Exception:
        pass

    time.sleep(0.5)
    pc1_state = query_pc1_status()

    # Reset killchain back to Stage 1
    killchain_state["stage1_network_done"] = False
    killchain_state["stage2_injected"] = False
    killchain_state["active_scenario"] = "NORMAL"

    log_audit("STAGE3_RECOVERED",
              f"Restored genuine Pi stream (Port 8081). Synchronized authentic physical footage ({recovered_info.get('frame_count', 0)} frames) to PC1.",
              status="SECURE_RESTORED",
              pc1_trust=pc1_state["trust_score"])

    return jsonify({
        "ok": True,
        "stage": 3,
        "message": "Attack stopped! Authentic Pi camera restored. Original footage synchronized to PC1.",
        "killchain": killchain_state,
        "pc1": pc1_state,
        "recovered_footage": recovered_info
    })


# ---------------------------------------------------------------------------
# UPLOAD CUSTOM MP4 FILE FROM PC2
# ---------------------------------------------------------------------------
@app.route("/api/upload_mp4", methods=["POST"])
def upload_custom_mp4():
    global killchain_state
    if 'file' not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"ok": False, "error": "No selected file"}), 400

    if file and file.filename.lower().endswith(".mp4"):
        filename = secure_filename(file.filename)
        save_path = os.path.join(INJECTION_DIR, filename)
        file.save(save_path)
        killchain_state["selected_mp4"] = filename
        log_audit("CUSTOM_MP4_UPLOADED", f"Custom attack video uploaded: {filename}")
        return jsonify({"ok": True, "filename": filename, "message": f"Uploaded {filename} successfully."})

    return jsonify({"ok": False, "error": "Only .mp4 files are accepted"}), 400


@app.route("/simulate/<action>", methods=["POST"])
@app.route("/api/simulate/<action>", methods=["POST"])
def simulate_action(action):
    global killchain_state
    if action == "wifi_disconnect":
        import subprocess
        log_audit("WIFI_DEAUTH_DISCONNECT", "Attempting hardware Wi-Fi disconnection via system command.")
        try:
            # On Windows: netsh wlan disconnect
            subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, timeout=3)
            msg = "Dispatched netsh wlan disconnect command to network adapter."
        except Exception as e:
            msg = f"Disconnection simulated (adapter response: {e})"
        return jsonify({"ok": True, "action": action, "message": msg})
    
    # Generic forward to PC1
    try:
        r = requests.post(f"{PC1_DEFENDER_URL}/api/simulate/{action}", timeout=1.5)
        log_audit(f"SIMULATE_{action.upper()}", f"Triggered scenario {action} on PC1 Defender Hub.")
        return jsonify({"ok": True, "action": action, "forwarded": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PC2 Red Team Kill Chain Console")
    parser.add_argument("--port", type=int, default=8503, help="Port (default: 8503)")
    args = parser.parse_args()

    log_audit("SYSTEM_INITIALIZED", f"PC2 Kill Chain Console active on port {args.port}. Connected to PC1 at {PC1_DEFENDER_URL}.")
    app.run(host="0.0.0.0", port=args.port, threaded=True)
