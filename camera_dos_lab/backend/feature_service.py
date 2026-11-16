"""
feature_service.py - Manages feature metadata, clamping, and physical consistency rules.
"""

import json
from typing import Dict, Any, List, Tuple
from backend.config import FEATURES_PATH

class FeatureService:
    def __init__(self, features_path: str = FEATURES_PATH):
        self.features_path = features_path
        self.feature_meta: List[Dict[str, Any]] = []
        self.feature_map: Dict[str, Dict[str, Any]] = {}
        self.ordered_names: List[str] = []
        self.load_features()

    def load_features(self):
        with open(self.features_path, "r", encoding="utf-8") as f:
            self.feature_meta = json.load(f)
        self.ordered_names = [f["name"] for f in self.feature_meta]
        self.feature_map = {f["name"]: f for f in self.feature_meta}

    def get_features(self) -> List[Dict[str, Any]]:
        return self.feature_meta

    def clamp_vector(self, values: Dict[str, float]) -> Dict[str, float]:
        """Clamps values within their training 5th-99.9th percentile bounds."""
        clamped = {}
        for name, val in values.items():
            if name in self.feature_map:
                meta = self.feature_map[name]
                min_v = meta["min"]
                max_v = meta["max"]
                try:
                    num_val = float(val)
                    if num_val != num_val:  # NaN check
                        num_val = min_v
                    clamped[name] = max(min_v, min(max_v, num_val))
                except (ValueError, TypeError):
                    clamped[name] = min_v
            else:
                clamped[name] = float(val) if val == val else 0.0
        return clamped

    def link_derived_features(self, values: Dict[str, float]) -> Dict[str, float]:
        """
        Recomputes dependent features so vectors remain physically consistent:
        - Flow Bytes/s = total bytes / Flow Duration
        - Flow Packets/s = total packets / Flow Duration
        - Average Packet Size = total bytes / total packets
        """
        linked = dict(values)
        duration_us = max(10.0, float(linked.get("Flow Duration", 1000000.0)))
        duration_s = duration_us / 1000000.0

        fwd_pkts = max(0.0, float(linked.get("Total Fwd Packets", 1.0)))
        bwd_pkts = max(0.0, float(linked.get("Total Backward Packets", 0.0)))
        total_pkts = fwd_pkts + bwd_pkts

        fwd_len_mean = max(0.0, float(linked.get("Fwd Packet Length Mean", 40.0)))
        bwd_len_mean = max(0.0, float(linked.get("Bwd Packet Length Mean", 0.0)))

        total_bytes = (fwd_pkts * fwd_len_mean) + (bwd_pkts * bwd_len_mean)

        # Recompute rates
        linked["Flow Packets/s"] = round(total_pkts / duration_s, 2)
        linked["Flow Bytes/s"] = round(total_bytes / duration_s, 2)
        linked["Fwd Packets/s"] = round(fwd_pkts / duration_s, 2)
        linked["Bwd Packets/s"] = round(bwd_pkts / duration_s, 2)

        # Average Packet Size
        linked["Average Packet Size"] = round(total_bytes / max(1.0, total_pkts), 2)

        return self.clamp_vector(linked)

    def check_physical_consistency(self, values: Dict[str, float]) -> Tuple[bool, str]:
        """
        Validates physical consistency when link_derived is OFF.
        Returns (is_realistic, reason).
        """
        duration_us = float(values.get("Flow Duration", 1.0))
        duration_s = max(0.00001, duration_us / 1000000.0)
        
        fwd_pkts = float(values.get("Total Fwd Packets", 0.0))
        bwd_pkts = float(values.get("Total Backward Packets", 0.0))
        total_pkts = fwd_pkts + bwd_pkts

        flow_pkts_s = float(values.get("Flow Packets/s", 0.0))
        flow_bytes_s = float(values.get("Flow Bytes/s", 0.0))

        # Check: Packets/s vs Duration inconsistency
        expected_pkts_s = total_pkts / duration_s
        if total_pkts > 0 and abs(flow_pkts_s - expected_pkts_s) > max(100.0, expected_pkts_s * 2.0):
            return False, f"Flow Packets/s ({flow_pkts_s:.0f}) contradicts packets ({total_pkts:.0f}) over duration ({duration_s:.3f}s)"

        # Check: Bytes/s with 0 packets
        if total_pkts == 0 and flow_bytes_s > 1000.0:
            return False, "Flow Bytes/s is high but packet counts are zero"

        # Check: Flow IAT Mean greater than Flow Duration
        iat_mean = float(values.get("Flow IAT Mean", 0.0))
        if iat_mean > duration_us and total_pkts > 2:
            return False, f"Flow IAT Mean ({iat_mean:.0f} us) exceeds total Flow Duration ({duration_us:.0f} us)"

        return True, "Consistent"
