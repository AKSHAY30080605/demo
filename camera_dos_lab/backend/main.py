"""
main.py - FastAPI application orchestrating WebSockets, inference, and UI serving.
"""

import os
import time
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import HOST, PORT, BASE_DIR
from backend.feature_service import FeatureService
from backend.model_service import ModelService
from backend.explain import ExplainerService
from backend.live_source import LiveSource
from backend.profiles import ProfileService

app = FastAPI(title="Camera DoS Intrusion Detection Demo", version="2.0")

# Services
feature_service = FeatureService()
model_service = ModelService(feature_service)
explainer_service = ExplainerService(model_service, feature_service)
live_source = LiveSource()
profile_service = ProfileService()

# Global state
active_overrides: Dict[str, float] = {}
link_derived: bool = True
event_log: List[Dict[str, Any]] = []
last_verdict_label: str = "BENIGN"

# WebSocket connection registries
control_clients: Set[WebSocket] = set()
dashboard_clients: Set[WebSocket] = set()

class PredictRequest(BaseModel):
    vector: Dict[str, float]

def get_current_combined_vector() -> Dict[str, float]:
    """Combines live flow vector with current PC2 slider overrides."""
    live_vec = live_source.get_current()
    combined = dict(live_vec)
    combined.update(active_overrides)
    if link_derived:
        combined = feature_service.link_derived_features(combined)
    else:
        combined = feature_service.clamp_vector(combined)
    return combined

def compute_full_state() -> Dict[str, Any]:
    global last_verdict_label
    live_vec = live_source.get_current()
    mod_vec = get_current_combined_vector()

    is_realistic, reason = feature_service.check_physical_consistency(mod_vec)
    verdict = model_service.predict(mod_vec)
    explain = explainer_service.explain(mod_vec, verdict)
    boundary = explainer_service.compute_decision_boundary(mod_vec, verdict["label"])

    last_verdict_label = verdict.get("label", "BENIGN")

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "live": live_vec,
        "modified": mod_vec,
        "overrides": active_overrides,
        "verdict": verdict,
        "explain": explain,
        "boundary": boundary,
        "consistency": {
            "realistic": is_realistic,
            "reason": reason
        },
        "status": {
            "pc2_connected": len(control_clients) > 0,
            "control_count": len(control_clients),
            "dashboard_count": len(dashboard_clients),
            "frozen": live_source.frozen,
            "link_derived": link_derived
        },
        "event_log": event_log[-20:]
    }

import json
import urllib.request

INJECTION_DIR = Path(BASE_DIR).parent / "atm_trustfusion_ai" / "redteam_lab" / "attack_console" / "injection_videos"
os.makedirs(INJECTION_DIR, exist_ok=True)

def sync_to_pc1_defender(state: Dict[str, Any], inject_video: bool = False, mp4_file: str = "empty_atm_loop.mp4"):
    """Bridges PC2 actions directly to PC1 Defender Hub (Port 8502) & Pi camera recorder."""
    try:
        if inject_video:
            # 1. Instruct attack server on 8503 to prepare and loop the chosen fake video
            try:
                stage2_req = urllib.request.Request(
                    "http://127.0.0.1:8503/api/killchain/stage2_inject",
                    data=json.dumps({"mp4_file": mp4_file}).encode(),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(stage2_req, timeout=1.5)
            except Exception:
                pass

            # 2. Divert PC1 video source to rogue stream and flag loop/replay attack
            req = urllib.request.Request(
                "http://127.0.0.1:8502/api/set_source",
                data=json.dumps({"source": "http://127.0.0.1:8503/rogue_stream.mjpg"}).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=1.0)
            urllib.request.urlopen("http://127.0.0.1:8502/api/simulate/LOOP", data=b"", timeout=1.0)
            urllib.request.urlopen("http://127.0.0.1:8502/api/simulate/STAGE2_MP4_INJECTED", data=b"", timeout=1.0)

            # 3. Trigger authentic physical recording on Pi Camera Node!
            try:
                urllib.request.urlopen("http://127.0.0.1:8502/api/edge_recording/start", data=b"", timeout=1.0)
                print(f"[PiEdgeNode] Attack/Replay Active! Pi continuous recorder started for '{mp4_file}'.")
            except Exception:
                pass
            return

        v = state.get("verdict", {})
        lbl = v.get("label", "BENIGN")
        overrides = state.get("overrides", {})

        # If benign and no overrides: attack stopped. Sync Pi recorded footage to PC1 and DELETE on Pi!
        if not overrides and lbl == "BENIGN":
            try:
                urllib.request.urlopen("http://127.0.0.1:8502/api/edge_recording/stop_and_sync", data=b"", timeout=2.0)
                print("[PiEdgeNode] Attack ended! Authentic evidence synced to PC1 & deleted from Pi storage.")
            except Exception:
                pass
            urllib.request.urlopen("http://127.0.0.1:8502/api/reset_all", data=b"", timeout=1.0)
            return

        # An attack is active (SYN Flood, UDP Flood, Reflection, Slowloris, Slowhttptest, Hulk/GoldenEye, or slider packet flood)
        payload = json.dumps({"values": state.get("modified", {}), "verdict": v}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:8502/api/flow_override",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=1.0)

        sim_map = {
            "SYN Flood": "SYN_FLOOD",
            "UDP Flood": "UDP_FLOOD",
            "Reflection DNS/NTP": "AMPLIFICATION_DDOS",
            "Slowloris": "SLOWLORIS",
            "Slowhttptest": "SLOWHTTPTEST",
            "Hulk/GoldenEye": "HTTP_FLOOD"
        }
        if lbl in sim_map:
            urllib.request.urlopen(f"http://127.0.0.1:8502/api/simulate/{sim_map[lbl]}", data=b"", timeout=1.0)
        elif overrides:
            urllib.request.urlopen("http://127.0.0.1:8502/api/simulate/NET_FLOOD", data=b"", timeout=1.0)

        # WHATEVER ATTACK IS PERFORMED: Automatically trigger recording on Raspberry Pi camera node!
        try:
            urllib.request.urlopen("http://127.0.0.1:8502/api/edge_recording/start", data=b"", timeout=1.0)
            print(f"[PiEdgeNode] Attack '{lbl}' in progress! Pi camera node recording real physical scene.")
        except Exception:
            pass

    except Exception:
        pass

async def broadcast_state():
    state = compute_full_state()
    for ws in list(dashboard_clients):
        try:
            await ws.send_json(state)
        except Exception:
            dashboard_clients.discard(ws)
    for ws in list(control_clients):
        try:
            await ws.send_json(state)
        except Exception:
            control_clients.discard(ws)

def log_event(source: str, action: str, v_before: str, v_after: str):
    event_log.append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": source,
        "action": action,
        "verdict_before": v_before,
        "verdict_after": v_after
    })
    if len(event_log) > 60:
        event_log.pop(0)

# ----------------- REST Endpoints -----------------

@app.get("/api/features")
def get_features():
    return feature_service.get_features()

@app.get("/api/profiles")
def get_profiles():
    return profile_service.get_all()

@app.get("/api/health")
def get_health():
    return {
        "model_loaded": model_service.is_loaded,
        "classes": model_service.classes,
        "features_count": len(feature_service.ordered_names),
        "live_source_mode": live_source.mode,
        "pc2_connected": len(control_clients) > 0
    }

@app.get("/api/fake_videos")
def get_fake_videos():
    videos = []
    if INJECTION_DIR.exists():
        for f in os.listdir(INJECTION_DIR):
            if f.lower().endswith(".mp4"):
                videos.append(f)
    if not videos:
        videos = ["empty_atm_loop.mp4", "peaceful_corridor.mp4"]
    return {"ok": True, "videos": sorted(videos)}

@app.post("/api/upload_fake_video")
async def upload_fake_video(request: Request):
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    
    filename = "fake_attack_video.mp4"
    file_bytes = b""
    
    if "boundary=" in content_type:
        boundary_str = content_type.split("boundary=")[-1].strip().strip('"')
        boundary = boundary_str.encode()
        parts = body.split(b"--" + boundary)
        for part in parts:
            if b"Content-Disposition" in part and b"filename=" in part:
                headers_and_body = part.split(b"\r\n\r\n", 1)
                if len(headers_and_body) == 2:
                    header_bytes, part_body = headers_and_body
                    if part_body.endswith(b"\r\n"):
                        part_body = part_body[:-2]
                    for line in header_bytes.decode(errors="ignore").split("\r\n"):
                        if "filename=" in line:
                            fn = line.split("filename=")[-1].strip().strip('"').strip("'")
                            if fn:
                                filename = os.path.basename(fn)
                    file_bytes = part_body
                    break
    else:
        query_fn = request.query_params.get("filename")
        if query_fn:
            filename = os.path.basename(query_fn)
        file_bytes = body

    if not filename.lower().endswith(".mp4"):
        return JSONResponse({"ok": False, "error": "Only .mp4 video files are accepted"}, status_code=400)
    if not file_bytes:
        return JSONResponse({"ok": False, "error": "Uploaded video file is empty"}, status_code=400)

    clean_name = filename.replace(" ", "_")
    dest_path = INJECTION_DIR / clean_name
    try:
        INJECTION_DIR.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f_out:
            f_out.write(file_bytes)
        
        # Notify attack server on 8503 to prepare this file
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:8503/api/killchain/stage2_inject",
                data=json.dumps({"mp4_file": clean_name}).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=1.0)
        except Exception:
            pass
        
        return {"ok": True, "filename": clean_name, "message": f"Uploaded fake video '{clean_name}' successfully."}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

@app.post("/api/predict")
def predict_vector(req: PredictRequest):
    clamped = feature_service.clamp_vector(req.vector)
    return model_service.predict(clamped)

# ----------------- WebSockets -----------------

@app.websocket("/ws/control")
async def ws_control(websocket: WebSocket):
    await websocket.accept()
    control_clients.add(websocket)
    print(f"[WS] PC2 Control Panel connected from {websocket.client.host}")
    try:
        # Send initial state immediately
        await websocket.send_json(compute_full_state())
        while True:
            msg = await websocket.receive_json()
            m_type = msg.get("type")
            v_before = last_verdict_label

            if m_type == "override":
                new_vals = msg.get("values", {})
                active_overrides.update(new_vals)
                log_event("PC2 Sliders", f"Adjusted {list(new_vals.keys())}", v_before, "")
            elif m_type == "preset":
                name = msg.get("name", "benign")
                profile = profile_service.get_by_name(name)
                active_overrides.clear()
                active_overrides.update(profile)
                log_event("PC2 Preset", f"Applied {name}", v_before, "")
            elif m_type == "inject_video":
                mp4_file = msg.get("mp4_file", "empty_atm_loop.mp4")
                active_overrides["SYN Flag Count"] = 120
                log_event("PC2 Fake Video Injection", f"Injected fake video '{mp4_file}' & armed Pi edge recording", v_before, "REPLAY_ATTACK")
                sync_to_pc1_defender({}, inject_video=True, mp4_file=mp4_file)
            elif m_type == "reset":
                active_overrides.clear()
                log_event("PC2 Reset", "Restored live baseline & synced Pi evidence", v_before, "BENIGN")
                sync_to_pc1_defender(compute_full_state(), inject_video=False)
            elif m_type == "reset_single":
                f_name = msg.get("feature")
                if f_name in active_overrides:
                    del active_overrides[f_name]
                    log_event("PC2 Reset Single", f"Reset {f_name}", v_before, "")
            elif m_type == "freeze":
                live_source.set_freeze(bool(msg.get("value", False)))
                log_event("PC2 Freeze", f"Freeze: {live_source.frozen}", v_before, v_before)
            elif m_type == "toggle_link":
                global link_derived
                link_derived = bool(msg.get("value", True))
                log_event("PC2 Consistency", f"Link derived: {link_derived}", v_before, v_before)

            # Re-predict, sync to PC1 (Port 8502), and broadcast
            st = compute_full_state()
            if m_type != "inject_video":
                sync_to_pc1_defender(st, inject_video=False)
            await broadcast_state()
            if event_log:
                event_log[-1]["verdict_after"] = last_verdict_label

    except WebSocketDisconnect:
        control_clients.discard(websocket)
        print("[WS] PC2 Control disconnected.")
        await broadcast_state()

@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await websocket.accept()
    dashboard_clients.add(websocket)
    print(f"[WS] PC1 Dashboard connected from {websocket.client.host}")
    try:
        await websocket.send_json(compute_full_state())
        while True:
            # Dashboard is read-only receiver; keeps connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        dashboard_clients.discard(websocket)

# ----------------- Background Ticker -----------------

async def live_stream_ticker():
    """Advances live source by 1 row every second and broadcasts to all clients."""
    while True:
        await asyncio.sleep(1.0)
        live_source.step()
        await broadcast_state()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(live_stream_ticker())

# ----------------- UI Serving -----------------

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    dashboard_html = Path(BASE_DIR) / "frontend" / "dashboard" / "index.html"
    return HTMLResponse(content=dashboard_html.read_text(encoding="utf-8"))

@app.get("/control", response_class=HTMLResponse)
def serve_control():
    control_html = Path(BASE_DIR) / "frontend" / "control" / "index.html"
    return HTMLResponse(content=control_html.read_text(encoding="utf-8"))

if __name__ == "__main__":
    import uvicorn
    print(f"[*] Starting Camera-DoS Demo Server on {HOST}:{PORT}")
    print(f"[*] PC1 Dashboard:   http://localhost:{PORT}/")
    print(f"[*] PC2 Control UI:  http://<PC1-WIFI-IP>:{PORT}/control")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=False)
