# TrustFusion AI — ATM Surveillance & Anti-Tamper System

A split-computing surveillance platform tailored for the **ATM Sector** to defeat video loop / replay attacks, camera feed tampering, and network intrusion.

## The ATM Threat Model
In an ATM booth, attackers intercept the camera network feed (e.g. via ARP spoofing or camera exploit) and inject a **looped video recording of an empty ATM booth**. While security officers see an empty room, real intruders break open the ATM safe or install card skimmers.

**TrustFusion AI** solves this with a **3-Layer Cross-Fusion Engine**:

1. **Layer 1: Physical / Temporal Feed Dynamics (Replay Loop Detector)**
   - Employs a circular temporal hash autocorrelation buffer (16x16 downsampled structural signatures).
   - Detects when an empty room video is looped cyclically ($T$ seconds repetition) or frame sequences repeat.
   - Flags `VIDEO_REPLAY_LOOP`, `FROZEN_FEED`, `BLACK_FRAME`, `FEED_LOSS`.

2. **Layer 2: Network ML-IDS & Cryptographic Anti-Replay**
   - Pre-trained Gradient Boosted ML model (99.98% accuracy on 142,502 IoT-SFC flows).
   - Detects network exploits (`cameraTapoC200Attack`, `mitmArpSpoof`, `synFlood`, port scans).
   - Pi Camera node signs frame telemetry with HMAC-SHA256, monotonic `seq_no`, and fresh timestamp (`|t_now - t_cam| < 3.0s`). Unauthorized sources or replayed packets fail immediately (`AUTH_FAILURE`, `SEQ_REPLAY`).

3. **Layer 3: Content AI & Contextual Occupancy (YOLOv8)**
   - YOLOv8n object detection identifying `person`, `bag`, and room occupancy state (`ATM_EMPTY`, `ATM_OCCUPIED_NORMAL`, `ATM_MULTI_PERSON_RISK`).
   - Contextual Cross-Check: When Layer 1 detects a loop or freeze while Layer 3 sees 0 people, it triggers `ATM_LOOP_CONCEALMENT_ACTIVE`.

## Mathematical Trust Fusion Formulation
$$\text{Trust} = 100 \times (0.45 \cdot \text{Health}_{\text{feed}} + 0.35 \cdot \text{Health}_{\text{net}} + 0.20 \cdot \text{Health}_{\text{content}})$$
- **Green Zone ($\ge 75\%$)**: ATM Verified & Secure
- **Yellow Zone ($40\% - 74\%$)**: Elevated Caution
- **Red Zone ($< 40\%$)**: Critical Security Breach / Replay Attack (Alarms Triggered)

---

## How to Run

### 1. Central Analytics Hub (Laptop / Server)
```powershell
cd atm_trustfusion_ai
python app.py
```
Open **http://localhost:8502** in your browser.

### 2. Raspberry Pi Camera Node (Edge Device)
Copy `pi_node/camera_node.py` to the Raspberry Pi:
```bash
python3 camera_node.py --camera 0 --port 8080
```
Then on the dashboard (port 8502), click **Change Source** and paste:
`http://<pi-ip>:8080/video`
