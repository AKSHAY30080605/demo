# Camera-DoS Intrusion Detection Interactive Demo

A high-performance two-machine web application for an interactive Camera-DoS intrusion detection demonstration over Wi-Fi.

## Architecture

```
  +-----------------------------------------------------------------------+
  |                     PC 1 (Detector & ML Host)                         |
  |                                                                       |
  |  +-------------------------+          +----------------------------+  |
  |  |   Detector Dashboard    |          |      FastAPI Backend       |  |
  |  |  http://localhost:8000/ | <======> |     Port 8000 (0.0.0.0)    |  |
  |  +-------------------------+    WS    |  - ML Inference Engine     |  |
  |                                       |  - Feature Attribution     |  |
  |                                       |  - Decision Boundary Sweep |  |
  |                                       |  - Live / Replay Feeder    |  |
  |                                       +-------------^--------------+  |
  +-----------------------------------------------------|-----------------+
                                                        |
                                                Wi-Fi WebSocket
                                          ws://<PC1-WIFI-IP>:8000/ws/control
                                                        |
  +-----------------------------------------------------v-----------------+
  |                    PC 2 (Control Station - Browser Only)              |
  |                                                                       |
  |  +-----------------------------------------------------------------+  |
  |  | Control Panel: http://<PC1-WIFI-IP>:8000/control                |  |
  |  | - 30 Dynamic Flow Sliders (Debounced ~100ms, Log/Linear)        |  |
  |  | - 7 Attack Presets (SYN Flood, UDP, Slowloris, Hulk, etc.)      |  |
  |  | - "Link Derived Features" & Physical Consistency Engine         |  |
  |  | - "Freeze Live Feed" Baseline Experimenter                      |  |
  |  +-----------------------------------------------------------------+  |
  +-----------------------------------------------------------------------+
```

---

## Safety Scope
> [!IMPORTANT]
> **SIMULATION OF NUMERIC FLOW-FEATURE VECTORS ONLY.**
> This application does **not** generate, replay, inject, or transmit raw network attack packets over the physical network interface or Wi-Fi airwaves. It operates exclusively by editing numeric flow-feature vectors (CICFlowMeter schema) in memory and running machine learning inference on the modified vectors to evaluate model sensitivity and decision boundaries.

---

## Key Features

1. **PC1 (Detector Dashboard — `http://localhost:8000/`)**:
   - **Big Verdict Card**: Live state (`BENIGN` in neon green or `ATTACK: <family>` in pulsating crimson) with exact confidence percentage.
   - **Multi-Class Probability Bar Chart**: Real-time probabilities across all 7 attack classes (`BENIGN`, `SYN Flood`, `UDP Flood`, `Reflection DNS/NTP`, `Slowloris`, `Slowhttptest`, `Hulk/GoldenEye`).
   - **Side-by-Side Comparison Table**: Feature name, Live Value, Modified Value, Delta % badge, and active override highlights.
   - **5-Minute Trend Timeline**: Rolling time-series chart tracking attack probability over time, highlighting operator interventions and verdict flip moments.
   - **"Why This Verdict" (Feature Attribution)**: Top 8 driving features calculated via standardized z-score deviation multiplied by model feature importances (or SHAP).
   - **Decision Boundary Sweeper**: Automatically identifies the most influential active feature and sweeps 25 points across its range to find the exact numerical threshold where the verdict flips.
   - **Event Log Table**: Real-time audit trail of slider changes, presets, and verdict transitions.
   - **System Telemetry**: PC2 connection status, network latency (ms), and live feed status.

2. **PC2 (Control Panel — `http://<PC1-WIFI-IP>:8000/control`)**:
   - Needs **only a standard web browser** (Chrome, Firefox, Safari, Edge); no local Python installation required on PC2.
   - **6 Feature Tabs**:
     1. `Timing`: Flow Duration, Flow IAT Mean/Std/Max/Min, Fwd IAT Total, Idle Mean/Max.
     2. `Rates`: Flow Bytes/s, Flow Packets/s, Fwd Packets/s, Bwd Packets/s.
     3. `Packets and sizes`: Total Fwd/Bwd Packets, Packet Length Mean/Max, Packet Length Std, Average Packet Size.
     4. `TCP flags`: SYN, ACK, FIN, RST, PSH counts.
     5. `Window and header`: Init_Win_bytes_forward/backward, Fwd Header Length.
     6. `Port and protocol`: Destination Port quick selector (80, 443, 53, 123, 8081) and Protocol toggle (6 TCP vs 17 UDP).
   - **One-Click Attack Presets**:
     - 🔴 `SYN Flood`
     - 🔴 `UDP Flood`
     - 🔴 `Reflection DNS/NTP`
     - 🔴 `Slowloris`
     - 🔴 `Slowhttptest`
     - 🔴 `Hulk / GoldenEye`
     - 🟢 `Back to Benign`
   - **Physics & Consistency Linking**:
     - `Link Derived Features` toggle (ON by default): automatically maintains physical relationships ($Flow\,Bytes/s = \frac{Total\,Bytes}{Duration}$, $Flow\,Pkts/s = \frac{Total\,Pkts}{Duration}$, etc.).
     - When turned OFF: allows independent feature testing and flags impossible combinations with an `"Unrealistic combination"` warning badge.
   - **Freeze Live Feed**: Holds the moving baseline still while experimenting with fine slider adjustments.

---

## Installation & Setup

### Prerequisites
- Python 3.9+ (Python 3.11 recommended)
- PC1 and PC2 connected to the **same Wi-Fi network**.

### Step 1: Install Dependencies on PC 1
```bash
cd camera_dos_lab
pip install -r requirements.txt
```

### Step 2: Verify or Retrain Model Artifacts
Generate the calibrated Random Forest classifier, Scaler, and feature schema:
```bash
python build_model.py
```
This generates:
- `models/model.joblib`: Multi-class classifier.
- `models/scaler.joblib`: StandardScaler for the 30 CICFlowMeter features.
- `models/label_encoder.joblib`: Class labels encoder.
- `models/feature_list.json`: Feature definitions, bounds, log-scales, and importance rankings.
- `models/profiles.json`: Median feature vectors for attack presets.
- `data/sample_flows.csv`: 120-row normal streaming camera replay dataset.

### Step 3: Configure Windows Firewall on PC 1 (Allow Wi-Fi Traffic)
To allow PC2 to connect to PC1 over Wi-Fi on port 8000, run PowerShell as Administrator on PC1:
```powershell
New-NetFirewallRule -DisplayName "Camera-DoS Lab Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

### Step 4: Launch the Server on PC 1
```bash
python -m backend.main
```
or via uvicorn directly:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

---

## Operating Instructions

### On PC 1 (Detector Dashboard)
1. Open a browser and navigate to:
   ```
   http://localhost:8000/
   ```
2. You will observe the live camera flow stream advancing every second with `BENIGN (100.0%)` verdict.

### On PC 2 (Control Station over Wi-Fi)
1. Find PC1's Wi-Fi IP address (e.g. `192.168.1.105` or run `ipconfig` on PC1).
2. On PC2, open any web browser and navigate to:
   ```
   http://<PC1-WIFI-IP>:8000/control
   ```
3. The connection pill in the header will turn green: `PC1 Connected`.

### Recommended Demonstration Scenarios

#### Scenario 1: One-Click SYN Flood
1. On PC2, click the **SYN Flood** preset button.
2. Observe PC1 instantly flip to `ATTACK: SYN Flood (100.0% CONFIDENCE)` in red.
3. Observe "Why This Verdict" on PC1 highlight `SYN Flag Count` and `Flow Duration`.
4. Observe the Decision Boundary card on PC1 calculate the exact threshold where reducing SYN Flag count flips the verdict back to BENIGN.
5. On PC2, click **Reset All to Live** or **Back to Benign**; PC1 restores to `BENIGN (100.0%)`.

#### Scenario 2: Fine-Tuning Near the Decision Boundary
1. On PC2, click **Freeze Live Feed** to stabilize the baseline.
2. Select the **TCP flags** tab and slowly drag `SYN Flag Count` upward.
3. Watch the Live vs Modified table on PC1 update in real time.
4. Watch the probability of `SYN Flood` increase from 0.00 to 0.40, and cross the decision boundary at ~150 packets.

#### Scenario 3: Physical Consistency & Model Sensitivity
1. On PC2, toggle **Link Derived Features** to **OFF**.
2. Select the **Rates** tab and push `Flow Packets/s` to 50,000 pkts/s while leaving Total Packets at 20.
3. Notice the amber badge appear: `"Unrealistic combination: Flow Packets/s contradicts Total Packets and Duration"`.
4. Toggle **Link Derived Features** back to **ON**; notice the app automatically recomputes physically consistent rates.

---

## Model Contract & Custom Models
To use your own trained model:
1. Save your scikit-learn or XGBoost model to `models/model.joblib`.
2. Save your scaler to `models/scaler.joblib`.
3. Save your label encoder to `models/label_encoder.joblib`.
4. Update `models/feature_list.json` with the ordered feature list your model was trained on.
5. The backend dynamically reads `feature_list.json`—no code changes required.

---

## Running Unit Tests
```bash
python -m unittest tests.test_pipeline
```
All 11 unit tests verify feature clamping, physical rate linking, model predictions, attribution calculations, and boundary sweeping.
