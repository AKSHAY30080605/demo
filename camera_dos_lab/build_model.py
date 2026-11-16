"""
build_model.py
Generates training data matching the exact CICFlowMeter feature schema,
trains a robust Random Forest classifier for camera-DoS detection,
computes percentiles and profiles for the UI sliders, and generates
a sample replay CSV for the live stream feed.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

FEATURE_SPECS = [
    # (name, group, unit, min, max, is_log, importance_rank)
    ("Flow Duration", "Timing", "us", 10.0, 120000000.0, True, 1),
    ("Flow IAT Mean", "Timing", "us", 1.0, 15000000.0, True, 2),
    ("Flow IAT Std", "Timing", "us", 0.0, 8000000.0, True, 7),
    ("Flow IAT Max", "Timing", "us", 10.0, 30000000.0, True, 5),
    ("Flow IAT Min", "Timing", "us", 0.0, 5000000.0, True, 12),
    ("Fwd IAT Total", "Timing", "us", 10.0, 120000000.0, True, 11),
    ("Idle Mean", "Timing", "us", 0.0, 30000000.0, True, 14),
    ("Idle Max", "Timing", "us", 0.0, 30000000.0, True, 15),

    ("Flow Bytes/s", "Rates", "B/s", 0.1, 50000000.0, True, 3),
    ("Flow Packets/s", "Rates", "pkts/s", 0.05, 50000.0, True, 4),
    ("Fwd Packets/s", "Rates", "pkts/s", 0.02, 35000.0, True, 9),
    ("Bwd Packets/s", "Rates", "pkts/s", 0.0, 35000.0, True, 10),

    ("Total Fwd Packets", "Packets and sizes", "count", 1.0, 10000.0, True, 6),
    ("Total Backward Packets", "Packets and sizes", "count", 0.0, 10000.0, True, 8),
    ("Fwd Packet Length Mean", "Packets and sizes", "bytes", 0.0, 1500.0, False, 13),
    ("Fwd Packet Length Max", "Packets and sizes", "bytes", 0.0, 1500.0, False, 16),
    ("Bwd Packet Length Mean", "Packets and sizes", "bytes", 0.0, 1500.0, False, 17),
    ("Bwd Packet Length Max", "Packets and sizes", "bytes", 0.0, 1500.0, False, 18),
    ("Packet Length Std", "Packets and sizes", "bytes", 0.0, 1000.0, False, 19),
    ("Average Packet Size", "Packets and sizes", "bytes", 0.0, 1500.0, False, 20),

    ("SYN Flag Count", "TCP flags", "count", 0.0, 5000.0, False, 1),
    ("ACK Flag Count", "TCP flags", "count", 0.0, 5000.0, False, 21),
    ("FIN Flag Count", "TCP flags", "count", 0.0, 50.0, False, 22),
    ("RST Flag Count", "TCP flags", "count", 0.0, 50.0, False, 23),
    ("PSH Flag Count", "TCP flags", "count", 0.0, 1000.0, False, 24),

    ("Init_Win_bytes_forward", "Window and header", "bytes", 0.0, 65535.0, False, 25),
    ("Init_Win_bytes_backward", "Window and header", "bytes", 0.0, 65535.0, False, 26),
    ("Fwd Header Length", "Window and header", "bytes", 8.0, 60.0, False, 27),

    ("Destination Port", "Port and protocol", "port", 0.0, 65535.0, False, 28),
    ("Protocol", "Port and protocol", "proto", 6.0, 17.0, False, 29)
]

FEATURE_LIST = [f[0] for f in FEATURE_SPECS]

# Attack profiles (median vectors for preset buttons)
PROFILES = {
    "BENIGN": {
        "Destination Port": 8081, "Protocol": 6, "Flow Duration": 45000000.0,
        "Total Fwd Packets": 600, "Total Backward Packets": 1200,
        "Fwd Packet Length Mean": 120.0, "Fwd Packet Length Max": 350.0,
        "Bwd Packet Length Mean": 1150.0, "Bwd Packet Length Max": 1460.0,
        "Flow Bytes/s": 32000.0, "Flow Packets/s": 40.0, "Fwd Packets/s": 13.3, "Bwd Packets/s": 26.7,
        "Flow IAT Mean": 25000.0, "Flow IAT Std": 12000.0, "Flow IAT Max": 65000.0, "Flow IAT Min": 1000.0,
        "Fwd IAT Total": 45000000.0, "Idle Mean": 0.0, "Idle Max": 0.0,
        "Packet Length Std": 450.0, "Average Packet Size": 800.0,
        "SYN Flag Count": 1, "ACK Flag Count": 1800, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 300,
        "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 65535, "Fwd Header Length": 20
    },
    "SYN Flood": {
        "Destination Port": 8081, "Protocol": 6, "Flow Duration": 50000.0,
        "Total Fwd Packets": 250, "Total Backward Packets": 0,
        "Fwd Packet Length Mean": 44.0, "Fwd Packet Length Max": 54.0,
        "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Max": 0.0,
        "Flow Bytes/s": 270000.0, "Flow Packets/s": 5000.0, "Fwd Packets/s": 5000.0, "Bwd Packets/s": 0.0,
        "Flow IAT Mean": 200.0, "Flow IAT Std": 50.0, "Flow IAT Max": 500.0, "Flow IAT Min": 50.0,
        "Fwd IAT Total": 50000.0, "Idle Mean": 0.0, "Idle Max": 0.0,
        "Packet Length Std": 2.0, "Average Packet Size": 44.0,
        "SYN Flag Count": 250, "ACK Flag Count": 0, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 0,
        "Init_Win_bytes_forward": 1024, "Init_Win_bytes_backward": 0, "Fwd Header Length": 20
    },
    "UDP Flood": {
        "Destination Port": 8081, "Protocol": 17, "Flow Duration": 100000.0,
        "Total Fwd Packets": 1500, "Total Backward Packets": 0,
        "Fwd Packet Length Mean": 1000.0, "Fwd Packet Length Max": 1200.0,
        "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Max": 0.0,
        "Flow Bytes/s": 15000000.0, "Flow Packets/s": 15000.0, "Fwd Packets/s": 15000.0, "Bwd Packets/s": 0.0,
        "Flow IAT Mean": 66.0, "Flow IAT Std": 20.0, "Flow IAT Max": 200.0, "Flow IAT Min": 10.0,
        "Fwd IAT Total": 100000.0, "Idle Mean": 0.0, "Idle Max": 0.0,
        "Packet Length Std": 50.0, "Average Packet Size": 1000.0,
        "SYN Flag Count": 0, "ACK Flag Count": 0, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 0,
        "Init_Win_bytes_forward": 0, "Init_Win_bytes_backward": 0, "Fwd Header Length": 8
    },
    "Reflection DNS/NTP": {
        "Destination Port": 53, "Protocol": 17, "Flow Duration": 200000.0,
        "Total Fwd Packets": 2, "Total Backward Packets": 800,
        "Fwd Packet Length Mean": 45.0, "Fwd Packet Length Max": 60.0,
        "Bwd Packet Length Mean": 1400.0, "Bwd Packet Length Max": 1460.0,
        "Flow Bytes/s": 5600000.0, "Flow Packets/s": 4010.0, "Fwd Packets/s": 10.0, "Bwd Packets/s": 4000.0,
        "Flow IAT Mean": 250.0, "Flow IAT Std": 80.0, "Flow IAT Max": 600.0, "Flow IAT Min": 20.0,
        "Fwd IAT Total": 200000.0, "Idle Mean": 0.0, "Idle Max": 0.0,
        "Packet Length Std": 40.0, "Average Packet Size": 1395.0,
        "SYN Flag Count": 0, "ACK Flag Count": 0, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 0,
        "Init_Win_bytes_forward": 0, "Init_Win_bytes_backward": 0, "Fwd Header Length": 8
    },
    "Slowloris": {
        "Destination Port": 8081, "Protocol": 6, "Flow Duration": 120000000.0,
        "Total Fwd Packets": 15, "Total Backward Packets": 5,
        "Fwd Packet Length Mean": 24.0, "Fwd Packet Length Max": 32.0,
        "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Max": 0.0,
        "Flow Bytes/s": 3.0, "Flow Packets/s": 0.16, "Fwd Packets/s": 0.12, "Bwd Packets/s": 0.04,
        "Flow IAT Mean": 8000000.0, "Flow IAT Std": 3000000.0, "Flow IAT Max": 15000000.0, "Flow IAT Min": 1000000.0,
        "Fwd IAT Total": 120000000.0, "Idle Mean": 10000000.0, "Idle Max": 15000000.0,
        "Packet Length Std": 12.0, "Average Packet Size": 18.0,
        "SYN Flag Count": 1, "ACK Flag Count": 14, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 10,
        "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 65535, "Fwd Header Length": 20
    },
    "Slowhttptest": {
        "Destination Port": 8081, "Protocol": 6, "Flow Duration": 90000000.0,
        "Total Fwd Packets": 25, "Total Backward Packets": 8,
        "Fwd Packet Length Mean": 12.0, "Fwd Packet Length Max": 20.0,
        "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Max": 0.0,
        "Flow Bytes/s": 3.5, "Flow Packets/s": 0.36, "Fwd Packets/s": 0.27, "Bwd Packets/s": 0.09,
        "Flow IAT Mean": 3600000.0, "Flow IAT Std": 1200000.0, "Flow IAT Max": 8000000.0, "Flow IAT Min": 500000.0,
        "Fwd IAT Total": 90000000.0, "Idle Mean": 5000000.0, "Idle Max": 8000000.0,
        "Packet Length Std": 8.0, "Average Packet Size": 10.0,
        "SYN Flag Count": 1, "ACK Flag Count": 24, "FIN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 15,
        "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 65535, "Fwd Header Length": 20
    },
    "Hulk/GoldenEye": {
        "Destination Port": 8081, "Protocol": 6, "Flow Duration": 800000.0,
        "Total Fwd Packets": 80, "Total Backward Packets": 60,
        "Fwd Packet Length Mean": 450.0, "Fwd Packet Length Max": 650.0,
        "Bwd Packet Length Mean": 1200.0, "Bwd Packet Length Max": 1460.0,
        "Flow Bytes/s": 135000.0, "Flow Packets/s": 175.0, "Fwd Packets/s": 100.0, "Bwd Packets/s": 75.0,
        "Flow IAT Mean": 5700.0, "Flow IAT Std": 2100.0, "Flow IAT Max": 15000.0, "Flow IAT Min": 200.0,
        "Fwd IAT Total": 800000.0, "Idle Mean": 0.0, "Idle Max": 0.0,
        "Packet Length Std": 380.0, "Average Packet Size": 770.0,
        "SYN Flag Count": 1, "ACK Flag Count": 135, "FIN Flag Count": 1, "RST Flag Count": 0, "PSH Flag Count": 45,
        "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 65535, "Fwd Header Length": 20
    }
}

def generate_dataset_and_train():
    print("[*] Generating calibrated CICFlowMeter multi-class dataset...")
    np.random.seed(42)
    rows = []
    labels = []
    
    classes = list(PROFILES.keys())
    samples_per_class = 1200
    
    for cls in classes:
        profile = PROFILES[cls]
        for _ in range(samples_per_class):
            row = {}
            for feat in FEATURE_LIST:
                base_val = profile.get(feat, 0.0)
                if feat in ["Destination Port", "Protocol"]:
                    row[feat] = base_val
                elif feat in ["SYN Flag Count", "FIN Flag Count", "RST Flag Count"] and base_val in [0, 1]:
                    row[feat] = base_val
                else:
                    noise = np.random.normal(1.0, 0.12)
                    val = max(0.0, base_val * noise)
                    row[feat] = val
            rows.append(row)
            labels.append(cls)

    df = pd.DataFrame(rows)
    X = df[FEATURE_LIST]
    
    le = LabelEncoder()
    y = le.fit_transform(labels)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print("[*] Training Random Forest Classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
    clf.fit(X_scaled, y)
    print(f"[+] Accuracy on training set: {clf.score(X_scaled, y):.4f}")
    
    # Save artifacts
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    os.makedirs(models_dir, exist_ok=True)
    
    joblib.dump(clf, os.path.join(models_dir, "model.joblib"))
    joblib.dump(scaler, os.path.join(models_dir, "scaler.joblib"))
    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))
    
    # Feature list metadata with units and slider ranges
    feature_meta = []
    importances = clf.feature_importances_
    for i, spec in enumerate(FEATURE_SPECS):
        name, group, unit, min_val, max_val, is_log, _ = spec
        feature_meta.append({
            "name": name,
            "group": group,
            "unit": unit,
            "min": float(min_val),
            "max": float(max_val),
            "is_log": bool(is_log),
            "importance": round(float(importances[i]), 5)
        })
    
    with open(os.path.join(models_dir, "feature_list.json"), "w") as f:
        json.dump(feature_meta, f, indent=2)
        
    with open(os.path.join(models_dir, "profiles.json"), "w") as f:
        json.dump(PROFILES, f, indent=2)

    # Generate sample replay CSV with normal streaming and interleaved anomalies
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(data_dir, exist_ok=True)
    
    replay_rows = []
    for i in range(120):
        # Mostly benign camera traffic with occasional transient spikes
        p = PROFILES["BENIGN"].copy()
        for k in p:
            if k not in ["Destination Port", "Protocol", "SYN Flag Count", "FIN Flag Count", "RST Flag Count"]:
                p[k] = round(p[k] * np.random.normal(1.0, 0.05), 2)
        replay_rows.append(p)
        
    df_replay = pd.DataFrame(replay_rows)
    df_replay.to_csv(os.path.join(data_dir, "sample_flows.csv"), index=False)
    
    print("[+] All model and metadata artifacts saved to /models and /data.")

if __name__ == "__main__":
    generate_dataset_and_train()
