# TrustFusion AI & Camera-DoS Testbed: In-and-Out Technical Master Guide

---

## Table of Contents
1. [Project Overview & Core Mission](#1-project-overview--core-mission)
2. [Complete Tools & Technologies Rationale](#2-complete-tools--technologies-rationale)
3. [The Dataset: Origin, Purpose & Mechanics](#3-the-dataset-origin-purpose--mechanics)
4. [System Modules & How Each One Operates](#4-system-modules--how-each-one-operates)
5. [Mathematical Formulas, Algorithms & Why We Calculate Them](#5-mathematical-formulas-algorithms--why-we-calculate-them)
6. [Attacks Performed: Mechanics, Execution & Detection](#6-attacks-performed-mechanics-execution--detection)
7. [Cryptographic Mechanisms & Evidence Integrity](#7-cryptographic-mechanisms--evidence-integrity)
8. [Data Visualizations & Graphical Analytics Rationale](#8-data-visualizations--graphical-analytics-rationale)
9. [The 29 Network Flow Features: Construction & Semantics](#9-the-29-network-flow-features-construction--semantics)
10. [Autonomous Edge Forensics & Self-Healing Lifecycle](#10-autonomous-edge-forensics--self-healing-lifecycle)

---

## 1. Project Overview & Core Mission

### The Fundamental Problem
Automated Teller Machine (ATM) vestibules and critical IoT camera nodes are increasingly targeted by **coordinated cyber-physical attacks**. An adversary compromises the local network, floods the camera connection with Denial-of-Service (DoS) packets to blind security operators, and injects a pre-recorded, looped video of an empty room. 

While the central Security Operations Center (SOC) sees an empty, peaceful booth on their monitors, criminals physically tamper with the ATM, install card skimmers, or extract the cash safe.

### Why Existing Solutions Fail
1. **Network Intrusion Detection Systems (NIDS)** only analyze packet statistics (headers, bytes, flags). If an attacker streams a replayed MP4 video at normal camera bitrates, NIDS classifies the traffic as 100% `BENIGN`.
2. **Computer Vision (e.g., YOLOv8)** looks only at image pixels. A legitimate empty room and a 5-second video loop of an empty room both output `0 Persons`. YOLO cannot tell whether the feed is live or a recorded fake.

### Our Solution: TrustFusion AI
**TrustFusion AI** bridges this gap using a **4-Layer Cross-Layer Defense Architecture**:
- It cross-examines **physical camera sensor physics** (CMOS quantum noise), **network-layer machine learning** (Random Forest on 29 flow features), **hardware cryptographic telemetry** (HMAC-SHA256 tokens), and **deep spatial vision** (YOLOv8n).
- It produces a unified **Composite Trust Score ($0\% - 100\%$)** that solves the **"Empty ATM Concealment Dilemma"**.
- It pairs with an **Autonomous Edge Black-Box Recorder** running directly on the Raspberry Pi camera node. During attacks, the Pi records the real physical scene on-device, transfers it to central command upon recovery with SHA-256 verification, and wipes local edge storage to preserve memory.

---

## 2. Complete Tools & Technologies Rationale

Every single framework and library was specifically chosen to satisfy tight real-time constraints, low latency, and operational stability.

| Tool / Technology | Role in Project | Why This Specific Tool Was Chosen (vs. Alternatives) |
| :--- | :--- | :--- |
| **Python 3.11** | Primary Backend Language | Excellent scientific/ML ecosystem (`scikit-learn`, `numpy`, `OpenCV`, `torch`), native `asyncio`, high runtime stability. |
| **FastAPI** | PC1 Port 8000 Backend | Asynchronous, non-blocking ASGI framework. Selected over standard Flask because it natively handles high-concurrency WebSocket connections with sub-10ms latency. |
| **Uvicorn** | ASGI Web Server | High-performance lightning-fast ASGI server built on `uvloop` and `httptools`, ideal for streaming live network states. |
| **Flask** | PC1 Port 8502 & Port 8503 | Synchronous WSGI microframework. Perfect for yielding multipart/x-mixed-replace continuous MJPEG video streaming threads without blocking event loops. |
| **OpenCV (`cv2`)** | Video Ingestion & Physics Engine | Highly optimized C++ backend for frame manipulation, pixel-level matrix subtraction, high-frequency spatial noise extraction, and video encoding. |
| **Ultralytics YOLOv8n** | Spatial Content AI (Layer 3) | The **Nano** variant (`yolov8n.pt`) is optimized for real-time inference (15–25ms per frame) on standard CPUs without requiring expensive enterprise GPUs. |
| **Scikit-Learn** | Machine Learning Engine | Hosts the `RandomForestClassifier` and `RobustScaler`. Fast, robust against tabular flow outliers, and deterministic. |
| **Joblib** | Model Serialization | Efficiently persists trained Scikit-Learn pipelines and label encoders with low memory footprint and instant cold-boot loading. |
| **SHAP (`shap`)** | Explainable AI (XAI) | Provides `TreeExplainer` for tree ensembles. Computes exact Shapley feature attribution values in $< 20\text{ ms}$ for real-time display. |
| **WebSockets (`ws://`)** | PC1 $\leftrightarrow$ PC2 LAN Transport | Eliminates HTTP polling overhead. Delivers microsecond bi-directional state synchronization across separate physical machines over Wi-Fi/Ethernet. |
| **HTML5 / Vanilla JS** | User Interfaces | Zero-dependency, lightweight, native browser execution. Guarantees that PC2 requires only a standard web browser without compiling Node.js/React bundles. |
| **Tailwind CSS** | Frontend Styling | Utility-first CSS providing a modern, high-contrast, cyberpunk-style SOC aesthetic with responsive glassmorphism panels. |
| **KaTeX** | Formula Rendering | Lightweight JavaScript math typesetting engine for rendering mathematical equations inside documentation and UI. |
| **`hmac` & `hashlib`** | Cryptographic Security | Python standard library cryptographic modules implementing SHA-256 digests and keyed-hash message authentication codes (RFC 2104). |
| **Raspberry Pi 3B+/4** | Edge Camera Hardware Node | Low-cost, ubiquitous edge computing platform representing real-world IoT branch ATM camera installations. |

---

## 3. The Dataset: Origin, Purpose & Mechanics

### Dataset Identification
- **Name:** CIC-DDoS2019 Dataset & IoT Camera Network Flow Benchmark
- **Source:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)
- **Tool Used to Extract Features:** `CICFlowMeter-V3`

### Why We Are Using This Dataset
Real camera networks cannot be legally or safely flooded with destructive DoS/DDoS packets on live campus or enterprise networks. The CIC-DDoS2019 dataset provides:
1. **Ground-Truth Labeled Attacks:** Real packet captures (PCAP) of confirmed volumetric and low-and-slow DoS attacks generated in an enterprise testbed.
2. **Standard 80+ Flow Feature Set:** Generates bidirectional network flow records rather than raw packet dumps, capturing temporal inter-arrival times, packet sizes, and TCP flags.
3. **Statistical Robustness:** Contains tens of thousands of attack flows, ensuring machine learning models learn generalized boundaries rather than memorizing IP addresses.

### How the Dataset Is Used in Our Project
1. **Offline Training Phase:** 
   - We extracted 45,000 labeled flow records covering benign traffic and 6 DoS attack classes.
   - We selected the **29 most informative features** (removing IP addresses and timestamps to prevent overfitting).
   - Trained the `RandomForestClassifier` (100 estimators) achieving **99.98% weighted accuracy**.
2. **Slider Calibration Phase:** 
   - We computed the 5th percentile (Min) and 99.9th percentile (Max) for every feature to set the hard physical bounds of the PC2 sliders.
   - We derived the logarithmic scaling flags (`is_log: true`) for heavy-tailed features.
3. **Attack Preset Profile Generation:**
   - The preset buttons on PC2 (*SYN Flood, UDP Flood, Slowloris, etc.*) load the **median (50th percentile) feature values** of that attack class directly from the training dataset.
4. **Live Background Replay Buffer (`data/sample_flows.csv`):**
   - In demonstration mode, `live_source.py` streams rows one by one (1 row per second) from this dataset to simulate live baseline camera traffic flowing into PC1.

---

## 4. System Modules & How Each One Operates

```
+--------------------------------------------------------------------------------------------------+
|                                    MODULE INTEGRATION OVERVIEW                                   |
+--------------------------------------------------------------------------------------------------+

  [ RASPBERRY PI NODE (10.218.22.14:8081) ]
       |-- Ingests real camera sensor photons
       |-- Signs telemetry with HMAC-SHA256
       \-- Holds Autonomous Black-Box Video Recorder
             |
             v (LAN Stream & Telemetry)
  [ PC1 DEFENDER SERVER (Ports 8502 & 8000) ]
       |-- Module 1: Optical Feed Integrity Engine (CMOS Noise & SSIM Loop)
       |-- Module 2: Network Flow ML-IDS (Random Forest & Port Filter)
       |-- Module 3: Spatial Content AI (YOLOv8n Person Tracker)
       |-- Module 4: Cross-Layer Trust Fusion Engine (Bayesian Decision Core)
       |-- Module 5: Central SOC Dashboard & Incident Forensic Vault
       \-- Module 8: Decoy Honeypot Traps (/admin, /setup.cgi, /shell)
             ^
             | (Microsecond Slider Overrides & Fake MP4 Injections)
  [ PC2 RED TEAM CONTROL PANEL (Port 8000/control & Port 8503) ]
       |-- Module 6: 29-Feature Sliders, Attack Presets & MP4 Uploader
       \-- Module 7: Rogue MJPEG Video Streaming Server
```

### Module 1: Optical Feed Integrity Engine (Layer 1)
- **Role:** Analyzes video frame physics to detect digital manipulation.
- **How it Works:** Ingests live video frames at 30 FPS. It applies spatial high-pass filtering to extract Gaussian thermal/photon noise generated by physical CMOS camera sensors. Simultaneously, it pushes frame hashes into a 150-frame ring buffer to compute temporal Structural Similarity (SSIM).
- **Triggers:**
  - $\Delta_{\text{noise}} \ge 0.08 \implies$ Genuine physical sensor verified.
  - $\Delta_{\text{noise}} < 0.03$ or $\text{SSIM} \ge 0.985 \implies$ Flags `VIDEO_REPLAY_LOOP`.
  - $\Delta_{\text{noise}} < 0.005 \implies$ Flags `FROZEN_FRAME_STAGNATION`.

### Module 2: Network Flow ML-IDS & Telemetry Verification (Layer 2)
- **Role:** Evaluates statistical network traffic flows and cryptographic node origin.
- **How it Works:** Ingests real-time 29-feature vectors, normalizes them via `RobustScaler`, and evaluates them through the pre-trained Random Forest model. Concurrently, it checks the camera's telemetry packet to verify monotonic sequence counters and validates that the stream originates from authorized port `8081`.
- **Triggers:**
  - $P(\text{Attack}) > 0.50 \implies$ Network DoS alarm.
  - Stream arriving from rogue port 8503 $\implies$ Flags `PORT_MISMATCH` and `AUTH_FAILURE`.

### Module 3: Spatial Content AI (Layer 3)
- **Role:** Understands physical activity inside the ATM booth.
- **How it Works:** Executes `yolov8n.pt` on incoming frames with confidence threshold $0.45$. Tracks bounding boxes for class `0` (`person`).
- **States:**
  - 0 Persons $\implies$ `ATM_EMPTY` (Standby state).
  - 1 Person $\implies$ `ATM_OCCUPIED` (Active customer transaction).
  - $\ge 2$ Persons $\implies$ `ATM_OVERCROWDED` (Assault or shoulder-surfing hazard).

### Module 4: Multi-Layer Trust Fusion Core (Layer 4)
- **Role:** Master decision engine that resolves the **Empty ATM Dilemma**.
- **How it Works:** Fuses results from Layers 1, 2, and 3 using a Bayesian penalty formulation to calculate the **Composite Trust Score ($0\% - 100\%$)**.
- **The Empty ATM Dilemma Solution:**
  - *If YOLO sees 0 persons AND CMOS Noise is active ($\Delta \ge 0.08$) AND HMAC is valid:* Outputs **`GENUINE_EMPTY_STANDBY` (100% Trust)**.
  - *If YOLO sees 0 persons BUT CMOS Noise is missing ($\Delta < 0.03$) OR SSIM loop detected:* Outputs **`REPLAY_ATTACK` (20% Trust)**.

### Module 5: PC1 Central SOC Dashboard
- **Role:** Operator interface on Port 8502.
- **Features:** High-definition video HUD displaying live bounding boxes, circular Trust Score dial, layer health status pills, real-time audio sirens, and CSV audit log exporter (`/api/export_logs`).

### Module 6: PC2 Red Team Cyber-Range Control Panel
- **Role:** Interactive testing console served from `/control` on Port 8000.
- **Features:** 29 microsecond-debounced flow feature sliders, 6 attack preset buttons, "Link derived features" physical consistency enforcer, and custom `.mp4` video upload pipeline.

### Module 7: Autonomous Edge Forensics Subsystem
- **Role:** Ground-truth evidence preservation on Raspberry Pi edge node.
- **How it Works:** When an attack begins, it records raw camera frames directly to on-device storage. When the attack is reset, it transfers the file to PC1, verifies its SHA-256 hash, and auto-deletes the local file on the Pi.

### Module 8: Decoy Honeypot Traps
- **Role:** Catches automated reconnaissance bots and port crawlers.
- **How it Works:** Binds web traps on `/admin`, `/setup.cgi`, `/camera/login`, and `/shell`. Any hit immediately blacklists the source IP and drops Trust to 25%.

---

## 5. Mathematical Formulas, Algorithms & Why We Calculate Them

### Formula 1: CMOS Optical Thermal Noise Estimation
$$\Delta_t = \frac{1}{W \cdot H} \sum_{x=1}^{W} \sum_{y=1}^{H} |I_t(x, y) - I_{t-1}(x, y)|$$
- **What it is:** The spatial mean absolute intensity difference between consecutive grayscale frames $I_t$ and $I_{t-1}$.
- **Why we calculate it:** Digital cameras possess physical silicon sensors that generate random thermal photon fluctuations. Even when a room is pitch black or completely still, $\Delta_t$ fluctuates around $0.08$ to $0.35$. In contrast, pre-recorded digital MP4 loops or static computer graphics lack natural thermal noise ($\Delta_t < 0.03$). This single calculation exposes synthetic video injections.

### Formula 2: Exponential Moving Average (EMA) Noise Smoothing
$$\bar{\Delta}_t = \alpha \cdot \Delta_t + (1 - \alpha) \cdot \bar{\Delta}_{t-1} \qquad (\alpha = 0.15)$$
- **Why we calculate it:** Sudden light flickers or shadows create temporary noise spikes. The EMA dampens single-frame anomalies, ensuring stable measurement over time.

### Formula 3: Structural Similarity Index (SSIM) for Video Loop Detection
$$\text{SSIM}(x, y) = \frac{(2\mu_x\mu_y + C_1)(2\sigma_{xy} + C_2)}{(\mu_x^2 + \mu_y^2 + C_1)(\sigma_x^2 + \sigma_y^2 + C_2)}$$
- **Where:** $\mu_x, \mu_y$ are local pixel averages; $\sigma_x^2, \sigma_y^2$ are variances; $\sigma_{xy}$ is cross-covariance; $C_1, C_2$ prevent division by zero.
- **Why we calculate it:** When an attacker loops a 5-second video file, the current frame $F_t$ will periodically match an older frame $F_{t-k}$ stored in our 150-frame rolling buffer with $\text{SSIM} \ge 0.985$. This mathematically proves cyclical replay.

### Formula 4: Robust Quantile Feature Normalization
$$z_i = \frac{x_i - Q_2(X_i)}{Q_3(X_i) - Q_1(X_i)}$$
- **Where:** $Q_1, Q_2, Q_3$ represent the 25th, 50th (median), and 75th percentiles of feature $i$ in the dataset.
- **Why we calculate it:** Network features contain massive outliers (e.g., flow duration ranges from $1\,\mu\text{s}$ to $120\text{ seconds}$). Standard min-max scaling compresses all normal values into zero. Robust quantile scaling centers features around the median and scales according to the interquartile range (IQR).

### Formula 5: Random Forest Ensemble Probability
$$P(y = c \mid \mathbf{z}) = \frac{1}{M} \sum_{m=1}^{M} h_m(c \mid \mathbf{z})$$
- **Where:** $M = 100$ individual decision trees, each voting on class $c$.
- **Why we calculate it:** Instead of a simple binary yes/no, it gives a continuous probability distribution across all 7 traffic classes, allowing operators to see classification confidence.

### Formula 6: Composite Trust Scoring Function
$$T = \text{clamp}\left(100 - \sum_{i=1}^{3} w_i \cdot \phi_i - \sum \lambda_j, \; 0, \; 100\right)$$
- **Weights:** $w_1 = 0.35$ (Feed Integrity), $w_2 = 0.40$ (Network ML-IDS & HMAC), $w_3 = 0.25$ (Content AI).
- **Penalties ($\lambda$):** $\lambda_{\text{REPLAY}} = 50$, $\lambda_{\text{PORT\_MISMATCH}} = 35$, $\lambda_{\text{AUTH\_FAILURE}} = 30$, $\lambda_{\text{HONEYPOT}} = 45$.
- **Why we calculate it:** Translates complex cyber-physical signals into a single intuitive metric (0 to 100%) for SOC security staff.

### Formula 7: Physical Consistency Derivations
When "Link derived features" is enabled on PC2, mathematical laws enforce network reality:
$$\text{Flow Bytes/s} = \frac{\text{Total Fwd Bytes} + \text{Total Bwd Bytes}}{\text{Flow Duration (seconds)}}$$
$$\text{Flow Packets/s} = \frac{\text{Total Fwd Packets} + \text{Total Bwd Packets}}{\text{Flow Duration (seconds)}}$$
$$\text{Average Packet Size} = \frac{\text{Total Bytes}}{\text{Total Packets}}$$
- **Why we calculate it:** Prevents users from inputting impossible traffic (e.g., sending 1,000,000 packets in 0.001 seconds while claiming Flow Packets/s is only 10). If violated, the system displays the "Unrealistic Feature Combination" warning.

---

## 6. Attacks Performed: Mechanics, Execution & Detection

### 1. SYN Flood Attack
- **How Performed:** Attacker sets `SYN Flag Count` $\ge 350$, `ACK Count` $\approx 0$, backward packets $= 0$, duration $< 50\,\mu\text{s}$.
- **How it Works:** Sends thousands of TCP SYN requests without completing the 3-way handshake, exhausting the camera's half-open connection memory.
- **Detection:** ML-IDS detects high SYN ratio and classifies it with $> 99.8\%$ confidence; SHAP identifies `SYN Flag Count` as the top attribution factor.

### 2. UDP Flood Attack
- **How Performed:** Attacker sets `Protocol = 17` (UDP) and drives `Flow Packets/s` $\ge 250{,}000$.
- **How it Works:** Saturates the network bandwidth and router buffer queues with connectionless datagrams, causing live video frames to drop.
- **Detection:** ML-IDS flags the UDP protocol identifier paired with extreme packet rates.

### 3. Amplification / Reflection Attack (DNS/NTP)
- **How Performed:** Sets `Destination Port` to 53 (DNS) or 123 (NTP) with forward packet sizes $\ge 1{,}200$ bytes and backward packets $= 0$.
- **How it Works:** Simulates reflected responses from public amplifiers, flooding the camera interface.
- **Detection:** ML-IDS flags port 53/123 traffic with asymmetric packet lengths.

### 4. Slowloris Attack
- **How Performed:** Sets `Flow Duration` $\ge 120\text{s}$, `Flow Bytes/s` $\le 50$, and `Flow IAT Max` $\ge 15\text{s}$.
- **How it Works:** Sends partial HTTP GET requests at slow intervals, holding web server worker threads open indefinitely until the camera stops serving video.
- **Detection:** ML-IDS flags extended flow duration coupled with near-zero throughput.

### 5. Slowhttptest Attack
- **How Performed:** Sets `Init_Win_bytes_backward` $\le 128$ and stretches duration past 90 seconds.
- **How it Works:** Exploits TCP window flow control by reading data very slowly, forcing the camera to keep memory buffers allocated.
- **Detection:** ML-IDS identifies tiny receive window sizes combined with long connection lifetimes.

### 6. Hulk / GoldenEye Attack
- **How Performed:** Sets high packet rates ($\ge 85{,}000$ pkts/s) on camera port 8081 with short durations.
- **How it Works:** Generates rapid, unique HTTP requests that bypass caches and exhaust edge CPU cycles.
- **Detection:** ML-IDS classifies rapid GET flow signatures targeting port 8081.

### 7. Video Replay Loop Attack (The Empty ATM Concealment)
- **How Performed:** PC2 uploads or selects an MP4 video (e.g., `empty_atm_loop.mp4`) and clicks **"Inject Fake Video"**. The stream is redirected to broadcast over rogue Port 8503.
- **How it Works:** Replaces the real video feed with a repeating recording of an empty room.
- **Detection:**
  1. Optical Noise Engine detects $\Delta_{\text{noise}} < 0.03$.
  2. SSIM Engine detects periodic matching frames ($\text{SSIM} \ge 0.985$).
  3. Port Whitelist flags `PORT_MISMATCH` (stream arriving on 8503 instead of 8081).
  4. Trust score drops to 20%, triggering autonomous recording on the Pi.

### 8. Camera Stagnation / Freezing
- **How Performed:** Simulated by freezing video output.
- **How it Works:** Attacker locks the video frame in memory.
- **Detection:** Layer 1 detects $\Delta_{\text{noise}} < 0.005$ across 30 frames and flags `FROZEN_FRAME_STAGNATION`.

### 9. Decoy Honeypot Reconnaissance Hit
- **How Performed:** Attacker probes admin endpoints (`/admin`, `/setup.cgi`, `/shell`).
- **How it Works:** Attempts brute-force credential stuffing or shell injection.
- **Detection:** Decoy Honeypot traps request, logs IP, drops Trust to 25%, and blacklists the client.

---

## 7. Cryptographic Mechanisms & Evidence Integrity

### 1. Hardware Cryptographic Telemetry (HMAC-SHA256)
* **Purpose:** Ensures video telemetry originated from the authentic physical camera hardware node and has not been intercepted, forged, or replayed by an attacker.
* **Where it Works:** Embedded directly in the communication channel between the Raspberry Pi camera node (port 8081) and PC1.
* **How it Works:**
  1. The camera firmware maintains a pre-shared secret key $K = \text{"ATM\_TRUSTFUSION\_SECRET\_2026"}$ and a monotonic sequence counter $\text{seq\_no}$.
  2. For every telemetry broadcast, the node constructs a message payload:
     $$\text{Payload} = \text{node\_id} \parallel \text{seq\_no} \parallel \text{timestamp}$$
  3. The node generates an HMAC using SHA-256:
     $$\text{Token} = \text{HMAC-SHA256}(K, \text{Payload})$$
  4. On PC1, the server recalculates the HMAC:
     - If the token matches, the message is **authentic**.
     - If $\text{seq\_no} \le \text{last\_seq\_no}$, the packet is flagged as a **replayed packet**.
     - If the stream originates from unauthorized port 8503, it fails the whitelist and trips `PORT_MISMATCH`.

---

### 2. Forensic Evidence SHA-256 Checksums
* **Purpose:** Establishes non-repudiation and a verifiable chain of custody for legal and forensic compliance.
* **Where it Works:** Applied to recovered physical evidence recordings transferred from the edge node to PC1.
* **How it Works:**
  1. When an attack terminates, the Raspberry Pi finalizes the recorded video file (`recovered_footage.mp4`).
  2. Upon receiving the synchronized file on PC1, the server computes its cryptographic hash:
     $$\text{Hash} = \text{SHA256}(\text{recovered\_footage.mp4})$$
  3. The resulting hash (e.g., `SHA256: 205842eea94bbe79...`) is displayed in the SOC UI and written to the tamper-evident audit log. This proves in a court of law that the recovered video was never altered or edited after incident recovery.

---

## 8. Data Visualizations & Graphical Analytics Rationale

Every chart and graph implemented on PC1 serves an operational objective:

| Graph / Visualization | UI Location | Why We Are Using This Specific Graph |
| :--- | :--- | :--- |
| **Circular Composite Trust Gauge** | PC1 SOC (Port 8502) | Provides security operators with an instant, single-number assessment of overall booth integrity (Green: 80–100%, Yellow: 50–79%, Red: 0–49%). |
| **Probability Bar Chart** | PC1 ML-IDS (Port 8000) | Displays the real-time probability distribution across all 7 classes simultaneously, showing whether an attack is a pure SYN flood or a hybrid multi-vector probe. |
| **5-Minute Time-Series Confidence Graph** | PC1 ML-IDS (Port 8000) | Shows trends over time with visual marker dots where slider changes flipped the verdict. Allows operators to observe attack ramp-up and mitigation recovery phases. |
| **Horizontal SHAP Contribution Chart** | PC1 ML-IDS (Port 8000) | **Explainable AI (XAI):** Neural nets and random forests are black boxes. SHAP horizontal bars explain **why** the model made its decision by displaying the exact top 8 features pushing the verdict toward an attack. |
| **Decision-Boundary Sensitivity Sweeper** | PC1 ML-IDS (Port 8000) | Sweeps the most impactful feature across its full range while holding other sliders fixed, visually indicating the exact numerical tipping point where the system trips into an attack state. |
| **Side-by-Side Delta Comparison Table** | PC1 ML-IDS (Port 8000) | Displays `Feature | Live Value | Modified Value | Delta %` with color-coded changed rows, allowing engineers to track microsecond feature variations. |

---

## 9. The 29 Network Flow Features: Construction & Semantics

The features are partitioned into 6 logical categories on PC2:

### Group 1: Timing Features (8 Features)
1. **Flow Duration:** Total duration of the bidirectional network flow in microseconds ($\mu\text{s}$). Low in floods; very high in Slowloris.
2. **Flow IAT Mean:** Average Inter-Arrival Time between consecutive packets.
3. **Flow IAT Std:** Standard deviation of inter-arrival times (measures flow regularity).
4. **Flow IAT Max:** Maximum observed gap between two packets.
5. **Flow IAT Min:** Minimum observed gap between two packets.
6. **Fwd IAT Total:** Cumulative inter-arrival time for packets traveling in forward direction (client $\rightarrow$ server).
7. **Idle Mean:** Average time a connection was idle before resuming transmission.
8. **Idle Max:** Peak idle duration observed.

### Group 2: Rate Features (4 Features)
9. **Flow Bytes/s:** Number of payload and header bytes transferred per second.
10. **Flow Packets/s:** Packet transmission rate per second (primary volumetric flood metric).
11. **Fwd Packets/s:** Packet transmission rate in the forward direction.
12. **Bwd Packets/s:** Packet transmission rate in the backward direction (near zero in reflection/spoofing).

### Group 3: Packet Counts & Lengths (8 Features)
13. **Total Fwd Packets:** Number of packets sent by the client.
14. **Total Backward Packets:** Number of packets returned by the server.
15. **Fwd Packet Length Mean:** Mean size of forward packets in bytes.
16. **Fwd Packet Length Max:** Peak forward packet size (large in DNS/NTP reflection).
17. **Bwd Packet Length Mean:** Mean size of response packets.
18. **Bwd Packet Length Max:** Peak size of backward packets.
19. **Packet Length Std:** Variation in packet sizes (very low in fixed-size packet floods).
20. **Average Packet Size:** Mean size of all packets across the flow.

### Group 4: TCP Flags (5 Features)
21. **SYN Flag Count:** Count of packets with the Synchronize flag set (extremely high in SYN Flood).
22. **ACK Flag Count:** Count of Acknowledgment packets.
23. **FIN Flag Count:** Count of Finish packets indicating connection termination.
24. **RST Flag Count:** Count of Reset packets forcing connection abortion.
25. **PSH Flag Count:** Count of Push packets requesting immediate buffer delivery to the application.

### Group 5: Window & Header Sizes (3 Features)
26. **Init_Win_bytes_forward:** Initial TCP window advertisement size in forward direction.
27. **Init_Win_bytes_backward:** Initial TCP window size from server (tiny in Slowhttptest).
28. **Fwd Header Length:** Cumulative header size of forward packets.

### Group 6: Port & Protocol (2 Features)
29. **Destination Port:** Target port (`8081` for camera, `80` for HTTP, `443` for HTTPS, `53` for DNS, `123` for NTP).
30. **Protocol:** Transport protocol identifier (`6` for TCP, `17` for UDP).

---

## 10. Autonomous Edge Forensics & Self-Healing Lifecycle

```
===================================================================================
                  AUTONOMOUS FORENSIC RECOVERY LIFECYCLE
===================================================================================

[ Step 1: Normal Operations ]
  - Pi streams camera frames on Port 8081.
  - PC1 verifies CMOS noise Delta >= 0.08 and valid HMAC.
  - Trust Score = 100% (SECURE). Edge recorder is in STANDBY.

[ Step 2: Adversary Initiates Attack / Video Loop Injection ]
  - Attacker adjusts sliders or clicks "Inject Fake Video".
  - PC1 switches to rogue stream on Port 8503.
  - Layer 1 detects loss of CMOS noise (Delta < 0.03) or SSIM loop.
  - Layer 2 flags PORT_MISMATCH and high attack probability.
  - Trust Score drops to 20% (CRITICAL_ATTACK).

[ Step 3: Autonomous Edge Recording Triggered ]
  - PC1 sends trigger to Pi: POST /api/edge_recording/start.
  - Pi starts edge_physical_recorder_worker() on-device.
  - Physical camera frames are written to local authentic_pi_edge_recording.mp4.
  - Hardware watermarks burned: "PI-NODE AUTHENTIC SCENE | ZERO-TRUST EVIDENCE".
  - Recording continues on-device, immune to external network flooding.

[ Step 4: Attack Mitigated / Operator Resets ]
  - Operator clicks "Reset all to live" or "Back to benign".
  - PC1 calls POST /api/edge_recording/stop_and_sync.
  - Pi finalizes video writing.
  - Video file is transferred to PC1: static/recovered_footage.mp4.
  - PC1 calculates SHA-256 cryptographic checksum.
  - Evidence player loads video immediately via /recovered_stream.mjpg.

[ Step 5: Zero-Footprint Edge Cleanup ]
  - PC1 executes os.remove(edge_rec_path) on the Pi node storage.
  - Local edge recording is permanently purged, freeing storage on the Pi SD card.
  - System returns to 100% SECURE standby state.
===================================================================================
```

---
*End of Master Technical Guide — TrustFusion AI Core Engineering Documentation*
