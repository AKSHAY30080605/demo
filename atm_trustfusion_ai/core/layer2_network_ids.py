"""
layer2_network_ids.py - Layer 2: Network Health, ML-IDS & Cryptographic Integrity
Specialized for ATM Surveillance:

Trained on the IoT-SFC Benchmark Dataset:
- Large-scale labeled network traffic dataset collected from a realistic multi-protocol IoT/IIoT testbed.
- Covers smart agriculture, smart manufacturing, and video surveillance.
- Physical testbed devices: ESP32 smart farm, serial temperature sensor, Tapo C200 IP camera, Modbus smart factory simulation.
- Multi-protocol Edge-Fog-Cloud architecture: MQTT, HTTP, CoAP, Modbus, TCP, UDP, and Wi-Fi.
- Ground Truth: 14 attack types executed sequentially in an isolated laboratory:
  1. scanning (Network reconnaissance / Nmap - 8.06%)
  2. HydraBruteForce (SSH brute-force dictionary attacks)
  3. HttpFlood (HTTP application layer flooding)
  4. synFlood (TCP SYN flooding - 3.09%)
  5. udpFlood (UDP volumetric flooding)
  6. slowloris (Low-bandwidth slow HTTP DoS)
  7. botnetSim (Mirai-style IoT botnet simulation)
  8. mitmArpSpoof (ARP spoofing / Man-in-the-Middle stream hijacking)
  9. mqtt_dos (MQTT broker publish exhaustion - 2.63%)
  10. mqtt_spoof (MQTT telemetry payload falsification)
  11. mqtt_brute_force (MQTT authentication guessing)
  12. mqtt_sniff (MQTT passive telemetry eavesdropping)
  13. mqtt_malformed (Malformed fuzzing packet injection)
  14. cameraTapoC200Attack (Targeted surveillance camera exploit - 1.84%)
- Scale: 49,902,287 records, 88 Zeek extracted columns (13.85 GB uncompressed).
"""

import os
import time
import hmac
import hashlib
import pickle
import numpy as np

# Comprehensive IoT-SFC 14-Attack Taxonomy & Surveillance Mitigation Matrix
IOTSFC_ATTACK_TAXONOMY = {
    "cameraTapoC200Attack": {
        "name": "Targeted Surveillance IP Camera Exploit",
        "description": "Exploit targeting physical camera hardware (Tapo C200). Involves buffer exhaustion, unauthorized stream manipulation, and RTSP cut.",
        "severity": "CRITICAL",
        "mitigation": "Isolate camera VLAN, drop unauthenticated RTSP control frames, enforce hardware HMAC token."
    },
    "mitmArpSpoof": {
        "name": "ARP Poisoning / Man-in-the-Middle Stream Hijack",
        "description": "Attacker poisons ARP table between camera and defender hub to intercept live video or inject rogue empty room loops.",
        "severity": "CRITICAL",
        "mitigation": "Enforce static ARP bindings, 802.1X port authentication, and TLS encrypted streams."
    },
    "synFlood": {
        "name": "TCP SYN Flood Denial of Service",
        "description": "Volumetric half-open TCP connection flood exhausting camera socket memory and inducing video lag.",
        "severity": "HIGH",
        "mitigation": "Enable TCP SYN cookies on camera node, rate-limit SYN packets per second."
    },
    "HttpFlood": {
        "name": "HTTP Application Layer Flood",
        "description": "Floods camera web server ports (8080/8081) with rapid HTTP requests to starve real-time frame transmission.",
        "severity": "HIGH",
        "mitigation": "Reverse proxy rate-limiting, drop non-whitelisted HTTP connection headers."
    },
    "HydraBruteForce": {
        "name": "SSH Credential Brute-Force",
        "description": "Automated dictionary attack against camera SSH management port (port 22) attempting credential takeover.",
        "severity": "HIGH",
        "mitigation": "Disable password authentication, enforce Ed25519 SSH keys, enable Fail2Ban jail."
    },
    "scanning": {
        "name": "Network Reconnaissance / Port Scan",
        "description": "Nmap scanning of camera surveillance ports (22, 80, 554, 8080, 8081) mapping attack surfaces.",
        "severity": "MEDIUM",
        "mitigation": "Enable firewall stealth drop mode, block rapid port sweep IPs."
    },
    "botnetSim": {
        "name": "Mirai-Style IoT Botnet DDoS Simulation",
        "description": "Coordinated attack from compromised edge devices attempting to overwhelm surveillance infrastructure.",
        "severity": "CRITICAL",
        "mitigation": "Outbound connection filtering, network traffic volume profiling."
    },
    "slowloris": {
        "name": "Slowloris Low-Bandwidth HTTP DoS",
        "description": "Holds camera web connections open indefinitely using incomplete HTTP headers to exhaust connection pool.",
        "severity": "HIGH",
        "mitigation": "Enforce minimum transfer rate and aggressive client keep-alive timeouts."
    },
    "udpFlood": {
        "name": "UDP Volumetric Packet Flood",
        "description": "Massive volume of spoofed UDP datagrams flooding camera network interface and inducing packet loss.",
        "severity": "HIGH",
        "mitigation": "Implement UDP ingress rate-limiting and drop fragmented packets."
    },
    "mqtt_dos": {
        "name": "MQTT Broker Denial of Service",
        "description": "Flooding broker publish queues with garbage telemetry packets to blind surveillance alerts.",
        "severity": "HIGH",
        "mitigation": "Enforce broker client authorization and per-client publish rate quotas."
    },
    "mqtt_spoof": {
        "name": "MQTT Sensor Telemetry Spoofing",
        "description": "Injecting forged sensor or sequence counters into camera telemetry topics to mask physical tampering.",
        "severity": "CRITICAL",
        "mitigation": "Enforce topic authorization ACLs and end-to-end payload HMAC verification."
    },
    "mqtt_sniff": {
        "name": "MQTT Telemetry Eavesdropping",
        "description": "Passive sniffing of unencrypted telemetry to harvest sequence counters and node IDs for replay attacks.",
        "severity": "MEDIUM",
        "mitigation": "Enforce TLS (MQTTS port 8883) with mutual certificate authentication."
    },
    "mqtt_malformed": {
        "name": "Malformed Packet Fuzzing",
        "description": "Sending non-conformant binary payloads to crash camera network daemons.",
        "severity": "HIGH",
        "mitigation": "Strict packet schema validation and buffer boundary bounds-checking."
    },
    "mqtt_brute_force": {
        "name": "MQTT Broker Credential Brute-Force",
        "description": "Credential spraying against telemetry broker login.",
        "severity": "MEDIUM",
        "mitigation": "Account lockout thresholds and client certificate auth."
    }
}

class Layer2NetworkIDS:
    def __init__(self, model_dir=None, shared_secret_key="ATM_TRUSTFUSION_SECRET_2026"):
        self.secret_key = shared_secret_key.encode("utf-8")
        self.last_seq_no = -1
        self.last_timestamp = 0.0
        
        # Load trained ML model and scaler
        self.model = None
        self.multi_model = None
        self.multi_encoder = None
        self.scaler = None
        self.features = []
        self.ml_ready = False
        
        if model_dir:
            self._load_model(model_dir)

    def _load_model(self, model_dir):
        model_path = os.path.join(model_dir, "network_ids_model.pkl")
        multi_path = os.path.join(model_dir, "network_ids_multiclass.pkl")
        scaler_path = os.path.join(model_dir, "network_ids_scaler.pkl")
        try:
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                with open(scaler_path, "rb") as f:
                    bundle = pickle.load(f)
                    self.scaler = bundle["scaler"]
                    self.features = bundle["features"]
                if os.path.exists(multi_path):
                    with open(multi_path, "rb") as f:
                        mbundle = pickle.load(f)
                        self.multi_model = mbundle["model"]
                        self.multi_encoder = mbundle["encoder"]
                self.ml_ready = True
                print("[Layer 2] ML Network IDS loaded successfully (Binary + Multiclass).")
            else:
                print(f"[Layer 2] Model files not found in {model_dir}. Running in rule/crypto mode.")
        except Exception as e:
            print(f"[Layer 2] Error loading ML model: {e}")

    def get_attack_metadata(self, attack_type):
        """Returns formal IoT-SFC threat metadata, severity, and security mitigations."""
        return IOTSFC_ATTACK_TAXONOMY.get(attack_type, {
            "name": attack_type,
            "description": "Network intrusion anomaly detected from IoT-SFC flow model.",
            "severity": "HIGH",
            "mitigation": "Inspect source IP, isolate stream, and enforce cryptographic telemetry."
        })

    def score_network_flow(self, flow_dict):
        """
        Scores incoming network flow using the trained ML models.
        Returns (is_attack: bool, attack_prob: float, attack_type: str)
        """
        if not self.ml_ready or not self.model:
            return False, 0.0, "normal"

        try:
            vec = [float(flow_dict.get(k, 0.0)) for k in self.features]
            X = np.array([vec])
            X_scaled = self.scaler.transform(X)
            prob = float(self.model.predict_proba(X_scaled)[0, 1])
            is_attack = prob > 0.50
            
            attack_type = "normal"
            if is_attack and self.multi_model is not None:
                m_pred = self.multi_model.predict(X_scaled)[0]
                attack_type = self.multi_encoder.inverse_transform([m_pred])[0]
                
            return is_attack, prob, attack_type
        except Exception:
            return False, 0.0, "normal"

    def verify_crypto_telemetry(self, node_id, seq_no, timestamp, client_hmac):
        """
        Verifies cryptographic integrity of the camera node telemetry.
        Guards against ATM video injection, unauthorized cameras, and replay attacks.
        """
        now = time.time()
        flags = {
            "auth_failure": False,
            "seq_replay": False,
            "timestamp_stale": False
        }
        
        # 1. Monotonic sequence counter check (Anti-Replay)
        if seq_no is not None:
            seq_val = int(seq_no)
            if seq_val < self.last_seq_no and self.last_seq_no != -1:
                flags["seq_replay"] = True
            else:
                self.last_seq_no = seq_val

        # 2. Timestamp freshness (Max 3.0s drift allowed for live ATM feed)
        if timestamp is not None:
            time_drift = abs(now - float(timestamp))
            if time_drift > 3.0:
                flags["timestamp_stale"] = True
            self.last_timestamp = timestamp

        # 3. HMAC-SHA256 signature verification
        if client_hmac:
            msg = f"{node_id}:{seq_no}:{timestamp}".encode("utf-8")
            expected_hmac = hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_hmac, str(client_hmac)):
                flags["auth_failure"] = True
        else:
            # Missing HMAC from camera node
            flags["auth_failure"] = True

        return flags

    def evaluate(self, latency_ms=None, http_status=200, telemetry=None, flow_stats=None):
        """
        Evaluates Layer 2 network health and security.
        Returns dict with network_health (0.0 to 1.0), flags, alerts, metrics.
        """
        flags = {
            "network_down": False,
            "high_latency": False,
            "auth_failure": False,
            "seq_replay": False,
            "timestamp_stale": False,
            "ids_attack_detected": False
        }
        scores = {}
        
        # Network connectivity and latency
        if http_status != 200:
            flags["network_down"] = True
            net_health_qos = 0.0
        elif latency_ms is None:
            net_health_qos = 0.9
        else:
            # G.114 standard ceiling 1000ms
            net_health_qos = max(0.2, 1.0 - (latency_ms / 1200.0))
            if latency_ms > 600.0:
                flags["high_latency"] = True

        # Cryptographic verification
        if telemetry:
            if telemetry.get("port_mismatch"):
                flags["port_mismatch"] = True
                flags["auth_failure"] = True
            crypto_flags = self.verify_crypto_telemetry(
                telemetry.get("node_id"),
                telemetry.get("seq_no"),
                telemetry.get("timestamp"),
                telemetry.get("hmac")
            )
            flags.update(crypto_flags)

        # ML IDS evaluation
        attack_prob = 0.0
        attack_type = "normal"
        attack_meta = {}
        if flow_stats:
            is_attack, attack_prob, attack_type = self.score_network_flow(flow_stats)
            if is_attack:
                flags["ids_attack_detected"] = True
                flags[f"attack_{attack_type.lower()}"] = True
                attack_meta = self.get_attack_metadata(attack_type)

        # Calculate composite network health
        crypto_penalty = 0.90 if (flags["auth_failure"] or flags["seq_replay"]) else (0.4 if flags["timestamp_stale"] else 0.0)
        ids_penalty = attack_prob if flags["ids_attack_detected"] else 0.0
        
        penalty = max(crypto_penalty, ids_penalty)
        net_health = round(max(0.0, net_health_qos * (1.0 - penalty)), 3)

        alerts = [k.upper() for k, v in flags.items() if v]

        return {
            "layer": "Layer 2 (Network & Cryptographic Security)",
            "flags": flags,
            "net_health": net_health,
            "latency_ms": latency_ms,
            "ids_attack_prob": round(attack_prob, 4),
            "attack_type": attack_type,
            "attack_meta": attack_meta,
            "alerts": alerts
        }
