"""
Comprehensive Evaluation Suite for CICIDS2017 Intrusion Detection.

Produces:
1. Per-Class Precision, Recall, and F1-Scores.
2. Overall Macro-F1 and Weighted-F1.
3. Binary Stage 1 ROC-AUC and PR-AUC metrics.
4. Confusion Matrix heatmap generation (saving high-res figure to disk).
5. Microsecond-resolution Inference Latency profiling (per flow and per 1,000 flows).
6. Multi-model summary comparison table.
"""

import os
import time
import tempfile
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional

# Ensure non-interactive headless matplotlib backend
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib_cicids")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
    f1_score,
    precision_score,
    recall_score
)


class NIDSEvaluator:
    """Evaluates NIDS models on flow data."""
    def __init__(self, output_dir: str = "eval_results"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.results_store: Dict[str, Dict[str, Any]] = {}

    def measure_latency(self, model, X_sample: pd.DataFrame, n_runs: int = 10) -> Tuple[float, float]:
        """
        Measures inference latency per flow and per 1,000 flows.
        Returns: (latency_per_flow_us, latency_per_1000_flows_ms)
        """
        # Warmup
        _ = model.predict(X_sample.iloc[:100])
        
        times = []
        n_flows = len(X_sample)
        for _ in range(n_runs):
            t0 = time.perf_counter()
            _ = model.predict(X_sample)
            t1 = time.perf_counter()
            times.append(t1 - t0)
            
        avg_total_sec = float(np.mean(times))
        latency_per_flow_sec = avg_total_sec / n_flows
        latency_per_flow_us = latency_per_flow_sec * 1e6
        latency_per_1000_flows_ms = latency_per_flow_sec * 1000 * 1000  # ms
        return latency_per_flow_us, latency_per_1000_flows_ms

    def evaluate_model(
        self,
        model_name: str,
        model,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        y_test_binary: pd.Series
    ) -> Dict[str, Any]:
        """
        Performs full evaluation on a trained TwoStageNIDS model.
        """
        print(f"\n{'='*75}")
        print(f"        EVALUATING MODEL: {model_name.upper()}")
        print(f"{'='*75}")

        # Measure Latency
        flow_us, ms_per_1k = self.measure_latency(model, X_test)
        print(f"  [Latency Profile] Per-flow: {flow_us:.2f} µs | Per-1,000 flows: {ms_per_1k:.2f} ms")

        # Run Predictions
        preds, s1_binary_preds, s1_attack_probs = model.predict(X_test)

        # Stage 1 Binary Metrics
        roc_auc = roc_auc_score(y_test_binary, s1_attack_probs)
        pr_auc = average_precision_score(y_test_binary, s1_attack_probs)
        s1_f1 = f1_score(y_test_binary, s1_binary_preds, zero_division=0)
        s1_recall = recall_score(y_test_binary, s1_binary_preds, zero_division=0)
        s1_precision = precision_score(y_test_binary, s1_binary_preds, zero_division=0)

        print(f"  [Stage 1 Binary] ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f} | F1: {s1_f1:.4f} | Recall: {s1_recall:.4f}")

        # Multiclass Full-Hierarchy Metrics
        unique_classes = sorted(list(set(y_test.unique()) | set(preds)))
        clf_report_dict = classification_report(
            y_test, preds, labels=unique_classes, output_dict=True, zero_division=0
        )
        macro_f1 = clf_report_dict["macro avg"]["f1-score"]
        weighted_f1 = clf_report_dict["weighted avg"]["f1-score"]

        print(f"  [End-to-End Multiclass] Macro-F1: {macro_f1:.4f} | Weighted-F1: {weighted_f1:.4f}")
        print("\n  Per-Class Performance Breakdown:")
        print(f"  {'Class':<28} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
        print("  " + "-"*70)
        for cls in unique_classes:
            metrics = clf_report_dict[cls]
            print(f"  {cls:<28} | {metrics['precision']:<10.4f} | {metrics['recall']:<10.4f} | {metrics['f1-score']:<10.4f} | {int(metrics['support']):<8}")
        print("  " + "-"*70)

        # Generate Confusion Matrix
        cm = confusion_matrix(y_test, preds, labels=unique_classes)
        self._plot_confusion_matrix(cm, unique_classes, model_name)

        # Generate ROC & PR Curves for Stage 1
        self._plot_roc_pr_curves(y_test_binary, s1_attack_probs, model_name, roc_auc, pr_auc)

        eval_summary = {
            "model_name": model_name,
            "train_time_sec": getattr(model, "train_time_sec", 0.0),
            "latency_per_flow_us": flow_us,
            "latency_1000_flows_ms": ms_per_1k,
            "stage1_roc_auc": roc_auc,
            "stage1_pr_auc": pr_auc,
            "stage1_f1": s1_f1,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "per_class": {cls: clf_report_dict[cls] for cls in unique_classes}
        }
        self.results_store[model_name] = eval_summary
        return eval_summary

    def _plot_confusion_matrix(self, cm: np.ndarray, labels: List[str], model_name: str):
        """Plots and saves normalized confusion matrix."""
        # Row-normalized (by true label count)
        cm_norm = cm.astype('float') / np.maximum(cm.sum(axis=1)[:, np.newaxis], 1)
        
        plt.figure(figsize=(12, 10))
        sns.heatmap(
            cm_norm,
            annot=True,
            fmt=".2f",
            cmap="Blues",
            xticklabels=labels,
            yticklabels=labels,
            cbar_kws={'label': 'Normalized Recall'}
        )
        plt.title(f"Confusion Matrix (Normalized) - {model_name.upper()}\nShows Misclassifications and DoS/Web Variant Blends", fontsize=13, pad=15)
        plt.xlabel("Predicted Label", fontsize=11)
        plt.ylabel("True Ground Truth Label", fontsize=11)
        plt.xticks(rotation=45, ha="right", fontsize=9)
        plt.yticks(rotation=0, fontsize=9)
        plt.tight_layout()
        
        plot_path = os.path.join(self.output_dir, f"confusion_matrix_{model_name.lower().replace(' ', '_')}.png")
        plt.savefig(plot_path, dpi=200)
        plt.close()
        print(f"  [Plot Saved] Confusion matrix saved to: {plot_path}")

    def _plot_roc_pr_curves(
        self, y_true: pd.Series, y_scores: np.ndarray, model_name: str, roc_auc: float, pr_auc: float
    ):
        """Plots Stage 1 Binary ROC and PR Curves."""
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        precision, recall, _ = precision_recall_curve(y_true, y_scores)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

        # ROC Curve
        ax1.plot(fpr, tpr, color="crimson", lw=2, label=f"ROC Curve (AUC = {roc_auc:.4f})")
        ax1.plot([0, 1], [0, 1], color="gray", linestyle="--")
        ax1.set_xlim([0.0, 1.0])
        ax1.set_ylim([0.0, 1.05])
        ax1.set_xlabel("False Positive Rate (FPR)")
        ax1.set_ylabel("True Positive Rate (TPR)")
        ax1.set_title(f"ROC Curve (Stage 1 Binary) - {model_name.upper()}")
        ax1.legend(loc="lower right")
        ax1.grid(True, alpha=0.3)

        # PR Curve
        ax2.plot(recall, precision, color="navy", lw=2, label=f"PR Curve (AUC = {pr_auc:.4f})")
        ax2.set_xlim([0.0, 1.0])
        ax2.set_ylim([0.0, 1.05])
        ax2.set_xlabel("Recall")
        ax2.set_ylabel("Precision")
        ax2.set_title(f"Precision-Recall Curve (Stage 1) - {model_name.upper()}")
        ax2.legend(loc="lower left")
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()
        plot_path = os.path.join(self.output_dir, f"roc_pr_curve_{model_name.lower().replace(' ', '_')}.png")
        plt.savefig(plot_path, dpi=200)
        plt.close()
        print(f"  [Plot Saved] ROC & PR curves saved to: {plot_path}")

    def generate_comparison_table(self) -> pd.DataFrame:
        """
        Creates the required comparative summary table across all tested model families.
        Columns: Model, Macro-F1, Weighted-F1, Stage 1 ROC-AUC, Training Time (s), Latency per 1k flows (ms).
        """
        rows = []
        for name, data in self.results_store.items():
            rows.append({
                "Model Family": name,
                "Macro-F1": f"{data['macro_f1']:.4f}",
                "Weighted-F1": f"{data['weighted_f1']:.4f}",
                "Stage 1 ROC-AUC": f"{data['stage1_roc_auc']:.4f}",
                "Stage 1 PR-AUC": f"{data['stage1_pr_auc']:.4f}",
                "Training Time (s)": f"{data['train_time_sec']:.2f}s",
                "Inference / 1,000 Flows": f"{data['latency_1000_flows_ms']:.2f} ms"
            })
            
        df_summary = pd.DataFrame(rows)
        return df_summary
