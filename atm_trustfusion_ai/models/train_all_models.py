"""
train_all_models.py - Unified AI Training Pipeline for TrustFusion AI
Trains:
  1. Layer 2 Network Flow IDS (Binary & Multiclass) on 142,502 IoT network flows.
  2. Cross-Layer AI Fusion Classifier on 2,000 multi-layer telemetry records.
Exports all models, scalers, confusion matrices, and feature importances for UI display.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))

def train_network_ids():
    print("\n" + "=" * 65)
    print("  [1/2] Training Layer 2 Network Intrusion Detection AI")
    print("=" * 65)
    csv_path = os.path.join(DATA_DIR, "network_flows_iot_sfc.csv")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df):,} network flow records.")

    features = [
        "orig_p", "resp_p", "duration", "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
    ]
    for col in features:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    X = df[features]
    y_bin = df["attack"].astype(int).values

    # Train Binary Attack Classifier
    X_tr, X_te, y_tr, y_te = train_test_split(X, y_bin, test_size=0.2, random_state=42, stratify=y_bin)
    scaler = StandardScaler()
    X_tr_sc = scaler.fit_transform(X_tr)
    X_te_sc = scaler.transform(X_te)

    binary_clf = HistGradientBoostingClassifier(max_iter=120, random_state=42)
    binary_clf.fit(X_tr_sc, y_tr)
    y_pred = binary_clf.predict(X_te_sc)
    probs = binary_clf.predict_proba(X_te_sc)[:, 1]
    roc_auc = float(roc_auc_score(y_te, probs))
    acc = float(np.mean(y_pred == y_te))

    print(f"  -> Binary IDS Accuracy: {acc*100:.2f}% | ROC-AUC: {roc_auc:.6f}")

    # Train Multiclass Attack Type Classifier (Camera Exploit, ARP Spoof, Scanning, etc.)
    counts = df["type_of_attack"].value_counts()
    valid_classes = counts[counts >= 50].index.tolist()
    df_multi = df[df["type_of_attack"].isin(valid_classes)].copy()

    X_m = df_multi[features]
    lbl_enc = LabelEncoder()
    y_m = lbl_enc.fit_transform(df_multi["type_of_attack"].astype(str))

    Xm_tr, Xm_te, ym_tr, ym_te = train_test_split(X_m, y_m, test_size=0.2, random_state=42, stratify=y_m)
    Xm_tr_sc = scaler.transform(Xm_tr)
    Xm_te_sc = scaler.transform(Xm_te)

    multi_clf = HistGradientBoostingClassifier(max_iter=100, random_state=42)
    multi_clf.fit(Xm_tr_sc, ym_tr)
    ym_pred = multi_clf.predict(Xm_te_sc)
    multi_acc = float(np.mean(ym_pred == ym_te))
    print(f"  -> Multiclass Attack Classifier Accuracy: {multi_acc*100:.2f}% ({len(valid_classes)} attack classes)")

    # Save Models
    with open(os.path.join(BASE_DIR, "network_ids_model.pkl"), "wb") as f:
        pickle.dump(binary_clf, f)
    with open(os.path.join(BASE_DIR, "network_ids_multiclass.pkl"), "wb") as f:
        pickle.dump({"model": multi_clf, "encoder": lbl_enc}, f)
    with open(os.path.join(BASE_DIR, "network_ids_scaler.pkl"), "wb") as f:
        pickle.dump({"scaler": scaler, "features": features}, f)

    net_metrics = {
        "dataset_name": "IoT-SFC v2 Network Flows",
        "total_flows": len(df),
        "test_accuracy": round(acc * 100, 2),
        "roc_auc": round(roc_auc, 6),
        "multiclass_accuracy": round(multi_acc * 100, 2),
        "attack_types": valid_classes,
        "features": features,
        "class_distribution": df["type_of_attack"].value_counts().to_dict()
    }
    with open(os.path.join(BASE_DIR, "network_metrics.json"), "w") as f:
        json.dump(net_metrics, f, indent=2)
    print("  [+] Layer 2 Network Models and Metrics Saved.")

def train_cross_layer_fusion():
    print("\n" + "=" * 65)
    print("  [2/2] Training Cross-Layer AI Trust Fusion Model")
    print("=" * 65)
    csv_path = os.path.join(DATA_DIR, "labeled_fusion_dataset.csv")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df):,} cross-layer telemetry records.")

    features = [
        "has_detection", "avg_confidence", "content_trust", "feed_trust",
        "network_trust", "motion_score", "staticness_score", "duplicate_score",
        "replay_score", "arp_anomaly", "unknown_device", "packet_rate_anomaly", "auth_anomaly"
    ]
    for c in features:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    target_col = "classification"
    enc = LabelEncoder()
    y = enc.fit_transform(df[target_col].astype(str))
    classes = enc.classes_.tolist()

    X = df[features]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)
    acc = float(np.mean(y_pred == y_te))
    cm = confusion_matrix(y_te, y_pred).tolist()
    feat_imp = {f: round(float(imp), 4) for f, imp in zip(features, clf.feature_importances_)}

    print(f"  -> Cross-Layer Fusion Classifier Accuracy: {acc*100:.2f}%")
    print("  -> Top Predictive Features:", sorted(feat_imp.items(), key=lambda x: x[1], reverse=True)[:5])

    # Save Model
    with open(os.path.join(BASE_DIR, "fusion_ai_model.pkl"), "wb") as f:
        pickle.dump({"model": clf, "encoder": enc, "features": features}, f)

    fusion_metrics = {
        "dataset_name": "Labeled Cross-Layer Surveillance Telemetry",
        "total_records": len(df),
        "test_accuracy": round(acc * 100, 2),
        "classes": classes,
        "features": features,
        "feature_importance": feat_imp,
        "confusion_matrix": cm,
        "class_distribution": df[target_col].value_counts().to_dict()
    }
    with open(os.path.join(BASE_DIR, "fusion_metrics.json"), "w") as f:
        json.dump(fusion_metrics, f, indent=2)
    print("  [+] Cross-Layer AI Fusion Model and Metrics Saved.")

if __name__ == "__main__":
    train_network_ids()
    train_cross_layer_fusion()
    print("\n" + "=" * 65)
    print("  [ALL AI MODELS SUCCESSFULLY TRAINED & PACKAGED]")
    print("=" * 65)
