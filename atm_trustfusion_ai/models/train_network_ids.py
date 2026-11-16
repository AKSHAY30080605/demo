"""
train_network_ids.py - Network Intrusion Detection Model Training
Trained on IoT-SFC v2 / Camera Network Flow Dataset (142,502 samples)
Produces:
  - models/network_ids_model.pkl (HistGradientBoosting / RandomForest)
  - models/network_ids_scaler.pkl (StandardScaler and feature mappings)
  - models/model_metrics.json (Evaluation report, ROC-AUC, Confusion Matrix)
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
    precision_recall_fscore_support
)

def train_ids(dataset_path, output_dir):
    print("=" * 60)
    print("  TrustFusion AI - Layer 2 Network IDS Training")
    print("=" * 60)
    print(f"[*] Loading dataset from: {dataset_path}")
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
        
    df = pd.read_csv(dataset_path)
    print(f"[+] Loaded {len(df):,} total network flow records.")

    # Canonical flow features (preventing identifier leakage like UID/IPs)
    numeric_features = [
        "orig_p", "resp_p", "duration", "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
    ]
    
    for col in numeric_features:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    X = df[numeric_features]
    y_binary = df["attack"].astype(int).values
    
    # Stratified split: 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=0.20, random_state=42, stratify=y_binary
    )
    print(f"[*] Training split: {len(X_train):,} samples | Test split: {len(X_test):,} samples")

    # Fit feature standard scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Training Gradient Boosted IDS Classifier (HistGradientBoosting)...")
    clf = HistGradientBoostingClassifier(
        max_iter=120,
        learning_rate=0.1,
        max_depth=8,
        random_state=42
    )
    clf.fit(X_train_scaled, y_train)
    print("[+] Model training complete!")

    # Evaluate
    y_pred = clf.predict(X_test_scaled)
    y_prob = clf.predict_proba(X_test_scaled)[:, 1]
    
    roc_auc = float(roc_auc_score(y_test, y_prob))
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    metrics = {
        "roc_auc": round(roc_auc, 6),
        "precision": round(float(prec), 5),
        "recall": round(float(rec), 5),
        "f1_score": round(float(f1), 5),
        "confusion_matrix": cm,
        "features": numeric_features,
        "num_samples": len(df),
        "test_samples": len(X_test)
    }

    print("\n--- Model Evaluation Results ---")
    print(f"  ROC-AUC Score: {roc_auc:.6f}")
    print(f"  Weighted F1:   {f1:.5f}")
    print(f"  Accuracy:      {np.mean(y_pred == y_test)*100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], digits=4))

    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "network_ids_model.pkl")
    scaler_path = os.path.join(output_dir, "network_ids_scaler.pkl")
    metrics_path = os.path.join(output_dir, "model_metrics.json")

    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    with open(scaler_path, "wb") as f:
        pickle.dump({"scaler": scaler, "features": numeric_features}, f)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[+] Model saved to:  {model_path}")
    print(f"[+] Scaler saved to: {scaler_path}")
    print(f"[+] Metrics saved to: {metrics_path}")
    return metrics

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset = os.path.abspath(os.path.join(current_dir, "..", "..", "camera_sentinel", "data", "collected", "subset.csv"))
    train_ids(dataset, current_dir)
