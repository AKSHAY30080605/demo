"""
End-to-End Network Intrusion Detection System (NIDS) Pipeline on CICIDS2017.

Orchestrates all 7 stages:
1. Data Loading & Cleaning
2. Feature Engineering & Selection (Variance, Collinearity > 0.95, Tree Importance)
3. Handling Class Imbalance (Stratified Split, Adaptive SMOTE, Two-Stage Architecture)
4. Model Training & Comparison (XGBoost, Random Forest, Neural Network MLP)
5. Comprehensive Evaluation (Per-class F1, Macro-F1, Confusion Matrix, Latency profile)
6. Real-Time Streaming Ingestion & Retraining Feedback Loop
7. Summary Comparison & Decision Reporting
"""

import os
import sys
import argparse
import time
import pandas as pd
import numpy as np
from sklearn.metrics import f1_score

from cicids2017_nids.data_loader import (
    load_cicids2017_csvs,
    generate_benchmark_cicids2017,
    report_class_distribution,
    LABEL_COLUMN
)
from cicids2017_nids.feature_engineering import CICIDSFeatureSelector
from cicids2017_nids.imbalance_handler import ImbalanceHandler
from cicids2017_nids.models import TwoStageNIDS, run_stratified_kfold_cv
from cicids2017_nids.evaluation import NIDSEvaluator
from cicids2017_nids.streaming_engine import StreamingFlowConsumer


def run_pipeline(
    data_path: str = None,
    n_samples: int = 50000,
    model_families: list = None,
    use_smote: bool = True,
    output_dir: str = "eval_results",
    simulate_stream: bool = True
):
    if model_families is None:
        model_families = ["xgboost", "random_forest", "neural_network"]

    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "#"*80)
    print("      CICIDS2017 END-TO-END NETWORK INTRUSION DETECTION SYSTEM PIPELINE")
    print("#"*80)

    # =========================================================================
    # STAGE 1: DATA LOADING & CLEANING
    # =========================================================================
    print("\n>>> STAGE 1: DATA LOADING & CLEANING")
    if data_path and os.path.exists(data_path):
        print(f"Loading raw CICIDS2017 data from: {data_path}")
        df = load_cicids2017_csvs(data_path)
    else:
        print("No external CSV path provided or directory not found.")
        print(f"Generating calibrated benchmark dataset ({n_samples:,} flows) reproducing authentic CICIDS2017 schema...")
        df = generate_benchmark_cicids2017(n_samples=n_samples, random_state=42)

    # Report Class Distribution & Imbalance
    dist_report = report_class_distribution(df)
    dist_report.to_csv(os.path.join(output_dir, "cicids2017_class_distribution.csv"))

    X_raw = df.drop(columns=[LABEL_COLUMN])
    y_raw = df[LABEL_COLUMN]

    # =========================================================================
    # STAGE 2: FEATURE ENGINEERING & SELECTION
    # =========================================================================
    print("\n>>> STAGE 2: FEATURE ENGINEERING & SELECTION")
    selector = CICIDSFeatureSelector(variance_threshold=1e-4, correlation_threshold=0.95)
    X_selected = selector.fit_transform(X_raw, y_raw)

    # Save selected feature list & importances
    selector.feature_importances_.to_csv(os.path.join(output_dir, "feature_importances.csv"))

    # =========================================================================
    # STAGE 3: HANDLING CLASS IMBALANCE & DATA SPLITTING
    # =========================================================================
    print("\n>>> STAGE 3: HANDLING CLASS IMBALANCE & HIERARCHICAL PARTITIONING")
    handler = ImbalanceHandler(test_size=0.15, val_size=0.15, random_state=42)
    X_train, X_val, X_test, y_train, y_val, y_test = handler.stratified_split(X_selected, y_raw)

    y_train_binary = handler.prepare_stage1_binary_labels(y_train)
    y_val_binary = handler.prepare_stage1_binary_labels(y_val)
    y_test_binary = handler.prepare_stage1_binary_labels(y_test)

    # Stage 2 data: Malicious attacks only
    X_train_att, y_train_att = handler.prepare_stage2_multiclass_data(X_train, y_train)

    if use_smote:
        print("Applying Adaptive SMOTE to Stage 2 training data to balance minority attack classes...")
        X_train_att_resampled, y_train_att_resampled = handler.apply_adaptive_smote(
            X_train_att, y_train_att, target_minority_threshold=400
        )
    else:
        X_train_att_resampled, y_train_att_resampled = X_train_att, y_train_att

    # =========================================================================
    # STAGE 4: MODEL TRAINING & HYPERPARAMETER TUNING
    # =========================================================================
    print("\n>>> STAGE 4: MODEL TRAINING ACROSS 3 MODEL FAMILIES")
    trained_models = {}
    evaluator = NIDSEvaluator(output_dir=output_dir)

    for family in model_families:
        print(f"\n--- Training {family.upper()} Two-Stage Architecture ---")
        model = TwoStageNIDS(model_family=family, random_state=42)
        model.fit(
            X_train=X_train,
            y_train_raw=y_train,
            X_train_attacks=X_train_att_resampled,
            y_train_attacks=y_train_att_resampled
        )
        trained_models[family] = model

        # Validation set quick tune check
        val_preds, val_s1_bin, val_s1_prob = model.predict(X_val)
        val_macro_f1 = f1_score(y_val, val_preds, average='macro', zero_division=0)
        print(f"  [Validation Set Check] {family.upper()} Macro-F1: {val_macro_f1:.4f}")

    # =========================================================================
    # STAGE 5: COMPREHENSIVE EVALUATION & BENCHMARKING
    # =========================================================================
    print("\n>>> STAGE 5: COMPREHENSIVE TEST SET EVALUATION")
    for family, model in trained_models.items():
        evaluator.evaluate_model(
            model_name=family,
            model=model,
            X_test=X_test,
            y_test=y_test,
            y_test_binary=y_test_binary
        )

    # Comparative Summary Table
    comparison_table = evaluator.generate_comparison_table()
    table_csv_path = os.path.join(output_dir, "nids_model_comparison.csv")
    comparison_table.to_csv(table_csv_path, index=False)

    print("\n" + "="*85)
    print("                     NIDS MODEL PERFORMANCE COMPARISON SUMMARY")
    print("="*85)
    print(comparison_table.to_string(index=False))
    print("="*85)

    # =========================================================================
    # STAGE 6: REAL-TIME STREAMING & DEPLOYMENT SIMULATION
    # =========================================================================
    if simulate_stream:
        print("\n>>> STAGE 6: REAL-TIME STREAMING INGESTION & RETRAINING SIMULATION")
        # Deploy top performing model (XGBoost)
        best_model = trained_models.get("xgboost", list(trained_models.values())[0])
        stream_consumer = StreamingFlowConsumer(
            trained_nids_model=best_model,
            feature_selector=selector,
            theta_high=0.90,
            theta_low=0.50,
            retrain_threshold=5
        )

        print(f"Deploying streaming engine with dual confidence thresholds: [tau_low=0.50, tau_high=0.90]")
        # Simulate 100 live incoming flows from test set
        sample_indices = np.random.choice(len(X_test), size=100, replace=False)
        for idx in sample_indices:
            flow_dict = X_test.iloc[idx].to_dict()
            flow_dict["flow_id"] = f"FLOW-{idx:05d}"
            res = stream_consumer.process_incoming_flow(flow_dict)

        print(f"  Streaming Ingestion Report (100 flows processed):")
        print(f"    - Automated Firewall Drops (Auto-Blocked, Conf >= 0.90): {stream_consumer.total_auto_blocked}")
        print(f"    - Flagged for SOC Tier-2 Analyst Review (0.50 <= Conf < 0.90): {stream_consumer.total_analyst_flagged}")
        print(f"    - Benign / Low Threat Forwarded (Conf < 0.50): {stream_consumer.total_processed_flows - stream_consumer.total_auto_blocked - stream_consumer.total_analyst_flagged}")

        # Simulate SOC Analyst reviewing flagged flow and sending correction to retraining buffer
        if stream_consumer.analyst_review_queue:
            flagged_item = list(stream_consumer.analyst_review_queue)[0]
            flow_id = flagged_item["flow_id"]
            print(f"\n  [Analyst In Loop] SOC Analyst reviewing flagged flow: {flow_id} (Model suggested: {flagged_item['predicted_label']})")
            # Submit review
            review_res = stream_consumer.submit_analyst_review(flow_id, verified_ground_truth="DoS slowloris")
            print(f"  Analyst review submission result: {review_res}")

    print("\n" + "#"*80)
    print("      CICIDS2017 NIDS PIPELINE EXECUTION COMPLETED SUCCESSFULLY!")
    print(f"      All artifacts, metrics, and plots saved to: {output_dir}/")
    print("#"*80 + "\n")
    return comparison_table


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CICIDS2017 End-to-End NIDS Pipeline")
    parser.add_argument("--data_path", type=str, default=None, help="Directory containing CICIDS2017 CSVs or single CSV file")
    parser.add_argument("--samples", type=int, default=50000, help="Number of samples if generating benchmark dataset")
    parser.add_argument("--no_smote", action="store_true", help="Disable SMOTE resampling")
    parser.add_argument("--output_dir", type=str, default="eval_results", help="Directory to save figures and CSVs")
    
    args = parser.parse_args()
    run_pipeline(
        data_path=args.data_path,
        n_samples=args.samples,
        use_smote=not args.no_smote,
        output_dir=args.output_dir
    )
