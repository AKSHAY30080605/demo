"""
Real-Time Deployment, Streaming Ingestion, and Active Retraining Loop.

Features:
1. Live Flow Consumer: Processes streaming flow records from IPFIX/NetFlow/CICFlowMeter collectors.
2. Dual-Threshold Confidence Routing:
   - High Confidence (> theta_high, e.g. 0.90): Immediate automated firewall mitigation (AUTO_BLOCK).
   - Ambiguous / Borderline (theta_low <= conf < theta_high): Flagged for Tier-2 SOC Analyst inspection (FLAG_FOR_HUMAN_REVIEW).
   - Low Confidence (< theta_low): Forwarded as benign traffic (ALLOW_BENIGN).
3. Feedback & Active Retraining Buffer:
   - SOC analyst reviews ambiguous/misclassified flows.
   - Verified corrections enter a prioritized replay buffer.
   - Automatically triggers model update / warm-start retraining when drift/sample limit is reached.
"""

import time
import uuid
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple, Callable
from collections import deque


class StreamingFlowConsumer:
    """
    Simulates production ingestion of live NetFlow v9 / IPFIX / CICFlowMeter records
    with sub-millisecond classification, dual-threshold confidence gating, and analyst triage.
    """
    def __init__(
        self,
        trained_nids_model,
        feature_selector,
        theta_high: float = 0.90,
        theta_low: float = 0.50,
        retrain_threshold: int = 500
    ):
        self.model = trained_nids_model
        self.selector = feature_selector
        self.theta_high = theta_high
        self.theta_low = theta_low
        self.retrain_threshold = retrain_threshold

        # Operational Queues
        self.active_blocks: List[Dict[str, Any]] = []
        self.analyst_review_queue: deque = deque(maxlen=2000)
        self.retraining_buffer: List[Dict[str, Any]] = []
        self.total_processed_flows: int = 0
        self.total_auto_blocked: int = 0
        self.total_analyst_flagged: int = 0

    def process_incoming_flow(self, raw_flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consumes a single streaming flow telemetry packet:
        1. Aligns with selected features.
        2. Executes hierarchical inference.
        3. Applies dual-threshold confidence policy.
        """
        self.total_processed_flows += 1
        flow_id = raw_flow_dict.get("flow_id", str(uuid.uuid4())[:8])

        # Convert single dictionary to DataFrame matching selected features
        df_single = pd.DataFrame([raw_flow_dict])
        # Ensure all expected columns exist
        for col in self.selector.selected_features_:
            if col not in df_single.columns:
                df_single[col] = 0.0

        df_filtered = df_single[self.selector.selected_features_]

        # Model Inference
        pred_label_arr, s1_bin_arr, s1_prob_arr = self.model.predict(df_filtered)
        predicted_label = pred_label_arr[0]
        attack_prob = float(s1_prob_arr[0])

        # Confidence Decision Routing
        if attack_prob >= self.theta_high:
            action = "AUTO_BLOCK"
            self.total_auto_blocked += 1
            record = {
                "flow_id": flow_id,
                "timestamp": time.time(),
                "action": action,
                "predicted_label": predicted_label,
                "confidence": attack_prob,
                "flow_details": raw_flow_dict
            }
            self.active_blocks.append(record)
        elif attack_prob >= self.theta_low:
            action = "FLAG_FOR_HUMAN_REVIEW"
            self.total_analyst_flagged += 1
            record = {
                "flow_id": flow_id,
                "timestamp": time.time(),
                "action": action,
                "predicted_label": predicted_label,
                "confidence": attack_prob,
                "flow_details": raw_flow_dict
            }
            self.analyst_review_queue.append(record)
        else:
            action = "ALLOW_BENIGN"
            record = {
                "flow_id": flow_id,
                "timestamp": time.time(),
                "action": action,
                "predicted_label": "BENIGN",
                "confidence": 1.0 - attack_prob,
                "flow_details": raw_flow_dict
            }

        return record

    def submit_analyst_review(self, flow_id: str, verified_ground_truth: str) -> Dict[str, Any]:
        """
        SOC Tier-2 analyst reviews a flagged flow:
        - If ground truth matches prediction, confirmed benign or malicious.
        - If model was mistaken (False Positive or False Negative), flow enters the Retraining Buffer.
        """
        # Find in analyst queue
        target_flow = None
        for item in list(self.analyst_review_queue):
            if item["flow_id"] == flow_id:
                target_flow = item
                self.analyst_review_queue.remove(item)
                break

        if target_flow is None:
            return {"status": "error", "message": f"Flow {flow_id} not found in analyst queue."}

        was_misclassified = (target_flow["predicted_label"] != verified_ground_truth)
        
        if was_misclassified:
            entry = {
                "flow_id": flow_id,
                "features": target_flow["flow_details"],
                "model_prediction": target_flow["predicted_label"],
                "verified_label": verified_ground_truth,
                "confidence_at_test": target_flow["confidence"],
                "timestamp": time.time()
            }
            self.retraining_buffer.append(entry)
            print(f"[AnalystTriage] Misclassification confirmed on {flow_id} (Pred: {target_flow['predicted_label']} vs True: {verified_ground_truth}). Stored in Retraining Buffer ({len(self.retraining_buffer)}/{self.retrain_threshold}).")

        # Check if retraining trigger threshold is reached
        trigger_retrain = len(self.retraining_buffer) >= self.retrain_threshold
        return {
            "status": "reviewed",
            "flow_id": flow_id,
            "was_misclassified": was_misclassified,
            "buffer_size": len(self.retraining_buffer),
            "trigger_retrain_suggested": trigger_retrain
        }

    def execute_retraining_cycle(self) -> Dict[str, Any]:
        """
        Simulates flushing the retraining buffer and updating model boundaries.
        In production, this triggers an asynchronous Airflow or Kubeflow pipeline.
        """
        if not self.retraining_buffer:
            return {"status": "idle", "message": "Retraining buffer is empty."}

        buffer_count = len(self.retraining_buffer)
        print(f"\n[ActiveRetraining] Executing model retraining cycle with {buffer_count} analyst-verified edge cases...")
        
        # In a warm-start update, these edge cases receive 3x sample weighting
        # to prevent catastrophic forgetting while adjusting decision margins.
        time.sleep(0.5)  # Simulated model fine-tuning
        self.retraining_buffer.clear()
        
        print(f"[ActiveRetraining] Model update successfully deployed to production inference engine.")
        return {"status": "completed", "samples_incorporated": buffer_count}
