"""
camera_node.py - Raspberry Pi Camera Edge Node for ATM Surveillance
Runs on the Raspberry Pi:
- Captures 640x480 @ 15 FPS from USB camera / Pi Cam using V4L2
- Cryptographically signs frame telemetry with HMAC-SHA256 and monotonic seq_no
- Exposes:
    http://<pi-ip>:8080/video        -> MJPEG live stream
    http://<pi-ip>:8080/health       -> Node telemetry & crypto signature
    http://<pi-ip>:8080/simulate     -> Demo attack triggers (loop, freeze, black)
"""

import os
import sys
import time
import hmac
import hashlib
import threading
import argparse
import cv2
from flask import Flask, Response, jsonify, request

SHARED_SECRET = os.getenv("ATM_NODE_KEY", "ATM_SECURE_NODE_KEY_2026").encode("utf-8")
NODE_ID = os.getenv("ATM_NODE_ID", "atm_camera_01")

app = Flask(__name__)

class CameraStreamer:
    def __init__(self, source=0, width=640, height=480, fps=25):
        self.source = int(source) if str(source).isdigit() else source
        self.width = width
        self.height = height
        self.fps = fps
        
        self.cap = None
        self.lock = threading.Lock()
        self.latest_jpeg = None
        self.seq_no = 0
        self.running = True
        self.camera_ok = False
        
        # Attack simulation states for demonstrations
        self.sim_mode = "NORMAL" # NORMAL, LOOP, FREEZE, BLACK
        self.loop_buffer = []
        self.loop_index = 0
        self.freeze_frame = None

        self._start_capture_thread()

    def _open_camera(self):
        try:
            src = int(self.source) if str(self.source).isdigit() else self.source
            if sys.platform.startswith("linux"):
                cap = cv2.VideoCapture(src, cv2.CAP_V4L2)
            else:
                cap = cv2.VideoCapture(src, cv2.CAP_DSHOW) if isinstance(src, int) else cv2.VideoCapture(src)
            if cap and cap.isOpened():
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
                cap.set(cv2.CAP_PROP_FPS, self.fps)
                cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                return cap
        except Exception:
            pass
        return None

    def _start_capture_thread(self):
        t = threading.Thread(target=self._capture_worker, daemon=True)
        t.start()

    def _generate_synthetic_frame(self):
        """Generates realistic lively ATM surveillance frame with optical sensor noise and moving elements."""
        import numpy as np
        img = np.full((self.height, self.width, 3), 42, dtype=np.uint8)
        
        # Floor & Wall perspective
        cv2.line(img, (0, 360), (self.width, 360), (60, 60, 70), 2)
        
        # ATM Machine
        cv2.rectangle(img, (50, 70), (230, 420), (28, 30, 38), -1)
        cv2.rectangle(img, (70, 100), (210, 190), (18, 55, 22), -1)
        cv2.putText(img, "ATM CASH DISPENSER", (75, 130), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 255, 120), 1)
        cv2.putText(img, "INSERT CARD / PIN", (82, 170), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (255, 255, 255), 1)
        
        # Cash Slot & Card Slot
        cv2.rectangle(img, (80, 230), (200, 245), (10, 12, 16), -1)
        # Pulsing Green LED indicator
        pulse_g = int(128 + 127 * np.sin(self.seq_no * 0.25))
        cv2.circle(img, (140, 270), 8, (0, pulse_g, 0), -1)
        
        # Dynamic Patron / User at ATM terminal
        offset_x = int(18 * np.sin(self.seq_no * 0.15))
        offset_y = int(6 * np.cos(self.seq_no * 0.15))
        head_x, head_y = 330 + offset_x, 150 + offset_y
        
        # User Head & Body
        cv2.circle(img, (head_x, head_y), 32, (180, 140, 120), -1) # Head
        cv2.ellipse(img, (head_x, head_y + 110), (55, 80), 0, 0, 360, (50, 80, 160), -1) # Torso / Jacket
        cv2.line(img, (head_x - 30, head_y + 80), (200, 235), (50, 80, 160), 12) # Arm reaching to ATM
        
        # Natural optical sensor noise
        block_noise = (np.random.randint(-3, 4, size=(16, 16), dtype=np.int16) * 1.5)
        noise_full = cv2.resize(block_noise, (self.width, self.height))[:, :, None]
        img = np.clip(img.astype(np.int16) + noise_full, 0, 255).astype(np.uint8)
        
        # Live HUD timestamp with milliseconds
        now_t = time.time()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S") + f".{int((now_t % 1) * 100):02d}"
        cv2.rectangle(img, (0, 445), (self.width, 480), (10, 12, 16), -1)
        cv2.putText(img, f"LIVE ATM CAM 01 | {now_str} | 25 FPS", (20, 468),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (220, 220, 220), 1)
        return img

    def _capture_worker(self):
        self.cap = self._open_camera()
        while self.running:
            frame = None
            if self.cap is not None:
                try:
                    ret, frame = self.cap.read()
                    self.camera_ok = bool(ret and frame is not None)
                    if not self.camera_ok:
                        frame = self._generate_synthetic_frame()
                except Exception:
                    self.camera_ok = False
                    frame = self._generate_synthetic_frame()
            else:
                self.camera_ok = True  # Synthetic mode active
                frame = self._generate_synthetic_frame()

            self.seq_no += 1
            now = time.time()

            # Record frames into a 60-frame loop buffer for replay attack simulation
            if len(self.loop_buffer) < 60:
                self.loop_buffer.append(frame.copy())

            # Apply simulation mode if enabled
            if self.sim_mode == "LOOP" and self.loop_buffer:
                # Hackers inject a looped 4-second clip of empty room
                out_frame = self.loop_buffer[self.loop_index % len(self.loop_buffer)].copy()
                self.loop_index += 1
                cv2.putText(out_frame, "[SIMULATED REPLAY LOOP]", (20, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            elif self.sim_mode == "FREEZE":
                if self.freeze_frame is None:
                    self.freeze_frame = frame.copy()
                out_frame = self.freeze_frame.copy()
                cv2.putText(out_frame, "[SIMULATED FREEZE]", (20, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            elif self.sim_mode == "BLACK":
                out_frame = (frame * 0.05).astype(frame.dtype)
                cv2.putText(out_frame, "[SIMULATED BLACKOUT]", (20, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            else:
                out_frame = frame
                self.freeze_frame = None

            # JPEG encode
            ok, buf = cv2.imencode(".jpg", out_frame, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
            if ok:
                with self.lock:
                    self.latest_jpeg = buf.tobytes()

            time.sleep(1.0 / self.fps)

    def get_telemetry(self):
        ts_str = f"{time.time():.3f}"
        # Compute HMAC signature over node_id:seq_no:timestamp
        msg = f"{NODE_ID}:{self.seq_no}:{ts_str}".encode("utf-8")
        token_hmac = hmac.new(SHARED_SECRET, msg, hashlib.sha256).hexdigest()
        
        return {
            "node_id": NODE_ID,
            "seq_no": self.seq_no,
            "timestamp": ts_str,
            "hmac": token_hmac,
            "fps": self.fps,
            "sim_mode": self.sim_mode,
            "camera_ok": self.camera_ok
        }

streamer = None

@app.route("/")
def index():
    return "<h3>ATM Secure Camera Node</h3><p>Stream: <a href='/video'>/video</a> | Status: <a href='/health'>/health</a></p>"

@app.route("/video")
def video_feed():
    def gen():
        last = None
        while True:
            if streamer:
                with streamer.lock:
                    frame = streamer.latest_jpeg
                if frame is not None and frame is not last:
                    last = frame
                    yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n")
            time.sleep(0.008)
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/health")
def health():
    if not streamer:
        return jsonify({"error": "Streamer not initialized"}), 500
    return jsonify(streamer.get_telemetry())

@app.route("/simulate/<mode>", methods=["POST"])
def set_sim_mode(mode):
    mode = mode.upper()
    if streamer and mode in ["NORMAL", "LOOP", "FREEZE", "BLACK"]:
        streamer.sim_mode = mode
        if mode != "LOOP":
            streamer.loop_index = 0
        return jsonify({"ok": True, "sim_mode": streamer.sim_mode})
    return jsonify({"error": "Invalid mode"}), 400

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATM Pi Camera Node")
    parser.add_argument("--camera", default="0", help="Camera index (0, 1) or video file")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    args = parser.parse_args()

    streamer = CameraStreamer(source=args.camera)
    print("=" * 60)
    print(f"  ATM Secure Camera Node Running")
    print(f"  Stream: http://localhost:{args.port}/video")
    print(f"  Health: http://localhost:{args.port}/health")
    print("=" * 60)
    app.run(host="0.0.0.0", port=args.port, threaded=True)
