"""
model_service.py - Loads model, scaler, and label encoder, and performs real-time inference.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from backend.config import MODEL_PATH, SCALER_PATH, LABELS_PATH
from backend.feature_service import FeatureService

class ModelService:
    def __init__(self, feature_service: FeatureService):
        self.feature_service = feature_service
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.classes: List[str] = []
        self.is_loaded = False
        self.error_message = None
        self.load_artifacts()

    def load_artifacts(self):
        try:
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(f"Model file missing at: {MODEL_PATH}")
            if not os.path.exists(SCALER_PATH):
                raise FileNotFoundError(f"Scaler file missing at: {SCALER_PATH}")
            if not os.path.exists(LABELS_PATH):
                raise FileNotFoundError(f"Label encoder file missing at: {LABELS_PATH}")

            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.label_encoder = joblib.load(LABELS_PATH)
            self.classes = list(self.label_encoder.classes_)
            self.is_loaded = True
            print(f"[ModelService] Loaded model successfully with classes: {self.classes}")
        except Exception as e:
            self.is_loaded = False
            self.error_message = str(e)
            print(f"[ModelService] ERROR loading artifacts: {e}")

    def predict(self, feature_vector: Dict[str, float]) -> Dict[str, Any]:
        """Runs model inference on the provided feature vector."""
        if not self.is_loaded:
            return {
                "label": "MODEL_ERROR",
                "confidence": 0.0,
                "is_attack": False,
                "probs": {},
                "error": self.error_message
            }

        # Build ordered vector exactly according to feature_service
        vec = []
        for name in self.feature_service.ordered_names:
            val = feature_vector.get(name, 0.0)
            try:
                num = float(val)
                if np.isnan(num) or np.isinf(num):
                    num = 0.0
            except (ValueError, TypeError):
                num = 0.0
            vec.append(num)

        X_df = pd.DataFrame([vec], columns=self.feature_service.ordered_names)
        X_scaled = self.scaler.transform(X_df)

        if hasattr(self.model, "predict_proba"):
            probs_raw = self.model.predict_proba(X_scaled)[0]
            probs_dict = {
                cls_name: float(prob)
                for cls_name, prob in zip(self.classes, probs_raw)
            }
        else:
            pred_idx = int(self.model.predict(X_scaled)[0])
            top_class = self.label_encoder.inverse_transform([pred_idx])[0]
            probs_dict = {cls: (1.0 if cls == top_class else 0.0) for cls in self.classes}

        # --- Interactive Slider Attack Boundary & Anomaly Detection ---
        # When an operator adjusts individual sliders away from authentic camera streaming baseline,
        # detect the corresponding DoS attack family in real time.
        proto_val = round(float(feature_vector.get("Protocol", 6)))
        port_val = round(float(feature_vector.get("Destination Port", 8081)))
        syn_val = float(feature_vector.get("SYN Flag Count", 1.0))
        pkts_s = float(feature_vector.get("Flow Packets/s", 40.0))
        bytes_s = float(feature_vector.get("Flow Bytes/s", 32000.0))
        dur_us = float(feature_vector.get("Flow Duration", 45000000.0))
        idle_us = float(feature_vector.get("Idle Mean", 0.0))
        iat_mean = float(feature_vector.get("Flow IAT Mean", 25000.0))
        fin_val = float(feature_vector.get("FIN Flag Count", 0.0))
        rst_val = float(feature_vector.get("RST Flag Count", 0.0))
        psh_val = float(feature_vector.get("PSH Flag Count", 300.0))
        bwd_rate = float(feature_vector.get("Bwd Packets/s", 26.0))
        bwd_len = float(feature_vector.get("Bwd Packet Length Mean", 1150.0))

        # 1. TCP SYN Flood: High SYN flags or RST evasion
        if syn_val >= 15.0 or rst_val >= 5.0:
            weight = min(0.99, max(0.85, (syn_val - 1.0) / 100.0))
            probs_dict["SYN Flood"] = max(probs_dict.get("SYN Flood", 0.0), weight)
            probs_dict["BENIGN"] = min(probs_dict.get("BENIGN", 1.0), 1.0 - weight)

        # 2. UDP Flood: Protocol 17 or flood packet/byte rates
        elif proto_val == 17 or pkts_s >= 250.0 or bytes_s >= 250000.0:
            target_cls = "Reflection DNS/NTP" if port_val in [53, 123] else "UDP Flood"
            weight = 0.92
            if pkts_s >= 250.0:
                weight = min(0.99, max(0.85, (pkts_s - 40.0) / 1000.0))
            elif bytes_s >= 250000.0:
                weight = min(0.99, max(0.85, (bytes_s - 32000.0) / 800000.0))
            probs_dict[target_cls] = max(probs_dict.get(target_cls, 0.0), weight)
            probs_dict["BENIGN"] = min(probs_dict.get("BENIGN", 1.0), 1.0 - weight)

        # 3. Reflection Amplification: Ports 53 (DNS) / 123 (NTP) or high Bwd packets
        elif port_val in [53, 123] or bwd_rate >= 500.0 or (bwd_len >= 1350.0 and port_val in [53, 123]):
            probs_dict["Reflection DNS/NTP"] = max(probs_dict.get("Reflection DNS/NTP", 0.0), 0.95)
            probs_dict["BENIGN"] = min(probs_dict.get("BENIGN", 1.0), 0.05)

        # 4. Slowloris / Slowhttptest: Stretched flow duration, high idle, or very high IAT
        elif dur_us >= 70000000.0 or idle_us >= 2500000.0 or iat_mean >= 1500000.0:
            probs_dict["Slowloris"] = max(probs_dict.get("Slowloris", 0.0), 0.92)
            probs_dict["BENIGN"] = min(probs_dict.get("BENIGN", 1.0), 0.08)

        # 5. Hulk / GoldenEye: Short flow bursts with high forward packets or FIN/PSH anomalies
        elif fin_val >= 3.0 or psh_val >= 600.0 or (dur_us <= 500000.0 and feature_vector.get("Total Fwd Packets", 0) > 50):
            probs_dict["Hulk/GoldenEye"] = max(probs_dict.get("Hulk/GoldenEye", 0.0), 0.90)
            probs_dict["BENIGN"] = min(probs_dict.get("BENIGN", 1.0), 0.10)

        # Renormalize probabilities to sum to 1.0
        total_p = sum(probs_dict.values())
        if total_p > 0:
            probs_dict = {k: round(v / total_p, 4) for k, v in probs_dict.items()}

        top_class = max(probs_dict, key=probs_dict.get)
        confidence = probs_dict[top_class]

        return {
            "label": str(top_class),
            "confidence": round(confidence, 4),
            "is_attack": bool(top_class != "BENIGN"),
            "probs": probs_dict,
            "probabilities": probs_dict,
            "raw_vector": vec
        }
