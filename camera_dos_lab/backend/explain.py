"""
explain.py - Explains model decisions and computes interactive decision-boundary thresholds.
"""

import numpy as np
from typing import Dict, Any, List
from backend.model_service import ModelService
from backend.feature_service import FeatureService

class ExplainerService:
    def __init__(self, model_service: ModelService, feature_service: FeatureService):
        self.model_service = model_service
        self.feature_service = feature_service

    def explain(self, vector: Dict[str, float], verdict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Computes the top 8 features driving the prediction.
        Uses standardized z-score deviation multiplied by trained model feature importances.
        """
        if not self.model_service.is_loaded or "raw_vector" not in verdict:
            return []

        raw_vec = np.array([verdict["raw_vector"]])
        scaler = self.model_service.scaler
        mean = scaler.mean_
        scale = scaler.scale_

        # Z-scores: how far this flow deviates from typical training mean
        z_scores = np.abs((raw_vec[0] - mean) / np.maximum(scale, 1e-6))
        
        # Base importance weights from trained Random Forest
        if hasattr(self.model_service.model, "feature_importances_"):
            base_weights = self.model_service.model.feature_importances_
        else:
            base_weights = np.ones(len(self.feature_service.ordered_names)) / len(self.feature_service.ordered_names)

        # Attributed contribution score
        contributions = z_scores * base_weights
        total = np.sum(contributions) if np.sum(contributions) > 0 else 1.0
        normalized_contrib = (contributions / total) * 100.0

        items = []
        for i, name in enumerate(self.feature_service.ordered_names):
            meta = self.feature_service.feature_map.get(name, {})
            items.append({
                "feature": name,
                "contribution": round(float(normalized_contrib[i]), 1),
                "value": round(float(vector.get(name, 0.0)), 2),
                "unit": meta.get("unit", "")
            })

        # Return top 8 features by contribution
        items.sort(key=lambda x: x["contribution"], reverse=True)
        return items[:8]

    def compute_decision_boundary(self, vector: Dict[str, float], current_class: str) -> Dict[str, Any]:
        """
        Identifies the single most influential slider, sweeps it across 30 points
        while holding all other features fixed, and finds the threshold value where
        the verdict flips.
        """
        if not self.model_service.is_loaded:
            return {}

        # Pick top contributor or key attack-driver feature
        key_features = ["SYN Flag Count", "Flow Bytes/s", "Flow Packets/s", "Flow Duration", "Flow IAT Mean", "Destination Port"]
        
        # Determine candidate to sweep
        candidate = "Flow Bytes/s"
        for k in key_features:
            if k in vector and vector[k] > 0:
                candidate = k
                break

        meta = self.feature_service.feature_map.get(candidate, {})
        min_v = meta.get("min", 0.0)
        max_v = meta.get("max", 100000.0)
        is_log = meta.get("is_log", False)

        if is_log and min_v > 0 and max_v > min_v:
            sweep_vals = np.logspace(np.log10(max(0.1, min_v)), np.log10(max_v), num=25)
        else:
            sweep_vals = np.linspace(min_v, max_v, num=25)

        current_val = float(vector.get(candidate, sweep_vals[0]))
        flip_threshold = None
        flips_to = None

        # Sweep test vector
        test_vec = dict(vector)
        for val in sweep_vals:
            test_vec[candidate] = float(val)
            pred = self.model_service.predict(test_vec)
            if pred["label"] != current_class:
                flip_threshold = round(float(val), 2)
                flips_to = pred["label"]
                break

        return {
            "feature": candidate,
            "unit": meta.get("unit", ""),
            "current_value": round(current_val, 2),
            "flip_threshold": flip_threshold,
            "flips_to": flips_to,
            "explanation": (
                f"Adjusting '{candidate}' to {flip_threshold} {meta.get('unit', '')} flips verdict from {current_class} -> {flips_to}"
                if flip_threshold is not None
                else f"No class flip observed within standard range of '{candidate}'"
            )
        }
