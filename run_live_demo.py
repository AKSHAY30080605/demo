"""
Live Streaming NIDS Demonstration on CICIDS2017.

Features:
1. Automatically detects and loads daily CSVs from 'CICIDS2017/*.csv' if available.
2. If CSVs are not present, generates a calibrated realistic sample matching
   CICIDS2017 schema and exact attack types so the demo runs instantly.
3. Aligns features with the trained model's feature selector (preventing dimension mismatch).
4. Streams flows one by one with a simulated inter-arrival delay (default 0.2s - 0.4s).
5. Displays live matched/mismatched alerts and generates a final confusion matrix & classification report.
"""

import os
import glob
import time
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Safe headless backend for saving plots, or GUI if available
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

from cicids2017_nids.data_loader import (
    load_cicids2017_csvs,
    generate_benchmark_cicids2017,
    clean_dataframe,
    LABEL_COLUMN
)
from cicids2017_nids.feature_engineering import CICIDSFeatureSelector
from cicids2017_nids.models import TwoStageNIDS
from cicids2017_nids.imbalance_handler import ImbalanceHandler


class StandaloneNIDSWrapper:
    """
    Wraps the feature selector and TwoStageNIDS model so that a raw flow row
    can be passed directly to `model.predict(row)[0]` without feature mismatch errors.
    """
    def __init__(self, trained_model: TwoStageNIDS, selector: CICIDSFeatureSelector):
        self.model = trained_model
        self.selector = selector

    def predict(self, X_raw: pd.DataFrame) -> np.ndarray:
        # Align incoming features with what the model was trained on
        X_aligned = self.selector.transform(X_raw)
        final_preds, _, _ = self.model.predict(X_aligned)
        return final_preds


def prepare_demo_model_and_data(csv_folder: str = "CICIDS2017", samples_per_class: int = 15):
    """
    Prepares or loads data, trains the fast TwoStage XGBoost model,
    and constructs the balanced demo stream batch.
    """
    csv_files = glob.glob(os.path.join(csv_folder, "*.csv"))
    
    if csv_files:
        print(f"[LiveDemo] Found {len(csv_files)} CSV file(s) in '{csv_folder}/'. Loading...")
        df_list = [pd.read_csv(f, low_memory=False, encoding='cp1252') for f in csv_files]
        df = pd.concat(df_list, ignore_index=True)
        df = clean_dataframe(df, verbose=True)
    else:
        print(f"[LiveDemo] Notice: '{csv_folder}/' not found or empty.")
        print("          Generating a calibrated benchmark flow pool matching CICIDS2017 schema...")
        df = generate_benchmark_cicids2017(n_samples=25000, random_state=42)

    print(f"Total flows available: {len(df):,}")
    print("Class breakdown:\n", df[LABEL_COLUMN].value_counts().to_string())

    # Build Demo Batch: Sample N flows per attack type (plus benign)
    demo_rows = []
    unique_labels = df[LABEL_COLUMN].unique()
    for label in unique_labels:
        subset = df[df[LABEL_COLUMN] == label]
        n = min(samples_per_class, len(subset))
        demo_rows.append(subset.sample(n, random_state=42))

    demo_batch = pd.concat(demo_rows).sample(frac=1, random_state=1).reset_index(drop=True)
    print(f"\n[LiveDemo] Demo batch constructed: {len(demo_batch)} flows across {demo_batch[LABEL_COLUMN].nunique()} classes.")

    # Train the Two-Stage Model on background flows
    print("\n[LiveDemo] Training Two-Stage NIDS Model on training partition...")
    # Exclude demo batch rows from training to test true generalization
    train_pool = df.drop(index=demo_batch.index, errors='ignore')
    
    X_train_raw = train_pool.drop(columns=[LABEL_COLUMN])
    y_train_raw = train_pool[LABEL_COLUMN]

    # Feature selection
    selector = CICIDSFeatureSelector(variance_threshold=1e-4, correlation_threshold=0.95)
    X_train_sel = selector.fit_transform(X_train_raw, y_train_raw)

    # Imbalance handling and two-stage training
    handler = ImbalanceHandler(random_state=42)
    X_train_att, y_train_att = handler.prepare_stage2_multiclass_data(X_train_sel, y_train_raw)
    X_train_att_res, y_train_att_res = handler.apply_adaptive_smote(X_train_att, y_train_att, target_minority_threshold=300)

    model = TwoStageNIDS(model_family="xgboost", random_state=42)
    model.fit(
        X_train=X_train_sel,
        y_train_raw=y_train_raw,
        X_train_attacks=X_train_att_res,
        y_train_attacks=y_train_att_res
    )

    # Wrap model for seamless inference with raw input frames
    wrapped_model = StandaloneNIDSWrapper(trained_model=model, selector=selector)

    # Prepare features for the demo batch
    feature_cols = [c for c in demo_batch.columns if c != LABEL_COLUMN]
    X_demo = demo_batch[feature_cols]
    y_true = demo_batch[LABEL_COLUMN]

    return wrapped_model, X_demo, y_true


def run_demo(model, X_demo: pd.DataFrame, y_true: pd.Series, delay: float = 0.25) -> pd.DataFrame:
    """
    Streams through the trained model like a live network feed.
    """
    print("\n" + "="*80)
    print("                     STARTING LIVE NIDS STREAMING SIMULATION")
    print("="*80)
    correct = 0
    results = []
    total = len(X_demo)
    
    for i in range(total):
        row = X_demo.iloc[[i]]
        # Passes directly to model.predict(row)[0]
        pred = model.predict(row)[0]
        actual = y_true.iloc[i]
        match = "✓" if pred == actual else "✗"
        if pred == actual:
            correct += 1
            
        print(f"[{i+1:03d}/{total:03d}] True: {actual:<28} | Predicted: {pred:<28} {match}")
        results.append((actual, pred))
        if delay > 0:
            time.sleep(delay)  # simulate real-time inter-arrival

    acc = correct / total
    print("="*80)
    print(f"\nLive Stream Accuracy: {acc:.2%} ({correct}/{total} correctly classified)")
    return pd.DataFrame(results, columns=["actual", "predicted"])


def show_summary(results_df: pd.DataFrame, save_path: str = "demo_confusion_matrix.png"):
    """
    Displays the classification report and plots the live demo confusion matrix.
    """
    print("\n" + "="*70)
    print("                    DEMO CLASSIFICATION REPORT")
    print("="*70)
    unique_labels = sorted(results_df["actual"].unique())
    print(classification_report(results_df["actual"], results_df["predicted"], labels=unique_labels, zero_division=0))
    
    cm = confusion_matrix(results_df["actual"], results_df["predicted"], labels=unique_labels)
    
    plt.figure(figsize=(11, 9))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap="Blues",
        xticklabels=unique_labels,
        yticklabels=unique_labels
    )
    plt.xlabel("Predicted Label", fontsize=11)
    plt.ylabel("Actual Label", fontsize=11)
    plt.title("Demo Confusion Matrix — All Flow Attack Types", fontsize=13, pad=12)
    plt.xticks(rotation=45, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    
    plt.savefig(save_path, dpi=200)
    print(f"[Plot Saved] Confusion matrix heatmap saved to: {save_path}")
    print("="*70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Streaming NIDS Demonstration")
    parser.add_argument("--path", type=str, default="CICIDS2017", help="Path to CICIDS2017 CSV directory")
    parser.add_argument("--samples", type=int, default=10, help="Samples per attack class in demo batch")
    parser.add_argument("--delay", type=float, default=0.08, help="Simulated streaming delay per flow in seconds")
    parser.add_argument("--save_plot", type=str, default="demo_confusion_matrix.png", help="Path to save confusion matrix")
    
    args = parser.parse_args()
    
    model, X_demo, y_true = prepare_demo_model_and_data(csv_folder=args.path, samples_per_class=args.samples)
    results_df = run_demo(model, X_demo, y_true, delay=args.delay)
    show_summary(results_df, save_path=args.save_plot)
