"""
test_pipeline.py - Comprehensive Unit & Pipeline Tests for Camera-DoS Intrusion Detection Testbed.
"""

import unittest
import numpy as np
from pathlib import Path

from backend.config import BASE_DIR
from backend.feature_service import FeatureService
from backend.model_service import ModelService
from backend.explain import ExplainerService
from backend.profiles import ProfileService

class TestFeatureService(unittest.TestCase):
    def setUp(self):
        self.fs = FeatureService()

    def test_feature_list_loaded(self):
        """Verify feature list is loaded with ordered CICFlowMeter features."""
        self.assertGreaterEqual(len(self.fs.ordered_names), 29)
        self.assertIn("Flow Duration", self.fs.ordered_names)
        self.assertIn("SYN Flag Count", self.fs.ordered_names)
        self.assertIn("Destination Port", self.fs.ordered_names)

    def test_clamping(self):
        """Test that feature values are properly clamped to training percentiles."""
        test_vec = {
            "Flow Duration": -500.0,  # Below min (10.0)
            "SYN Flag Count": 99999.0  # Above max (5000.0)
        }
        clamped = self.fs.clamp_vector(test_vec)
        self.assertGreaterEqual(clamped["Flow Duration"], 10.0)
        self.assertLessEqual(clamped["SYN Flag Count"], 5000.0)

    def test_link_derived_features(self):
        """Test physical linking of derived rates and packet sizes."""
        raw_vec = {
            "Flow Duration": 2000000.0, # 2.0 seconds in us
            "Total Fwd Packets": 50.0,
            "Total Backward Packets": 50.0,
            "Fwd Packet Length Mean": 500.0,
            "Bwd Packet Length Mean": 500.0,
            "Flow Bytes/s": 10.0,  # Stale/incorrect
            "Flow Packets/s": 5.0   # Stale/incorrect
        }
        linked = self.fs.link_derived_features(raw_vec)
        # Total pkts = 100, duration = 2.0s -> Packets/s = 50.0
        self.assertAlmostEqual(linked["Flow Packets/s"], 50.0, places=1)
        # Total bytes = 50*500 + 50*500 = 50000, duration = 2.0s -> Bytes/s = 25000.0
        self.assertAlmostEqual(linked["Flow Bytes/s"], 25000.0, places=1)
        # Avg packet size = 500.0
        self.assertAlmostEqual(linked["Average Packet Size"], 500.0, places=1)

    def test_physical_consistency_check(self):
        """Test detection of unrealistic feature combinations when unlinked."""
        # Realistic case
        good_vec = {
            "Flow Duration": 1000000.0,
            "Total Fwd Packets": 10.0,
            "Total Backward Packets": 10.0,
            "Flow Packets/s": 20.0,
            "Flow Bytes/s": 15000.0
        }
        is_real, _ = self.fs.check_physical_consistency(good_vec)
        self.assertTrue(is_real)

        # Unrealistic: 100,000 pkts/s with only 2 total packets over 5 seconds
        bad_vec = {
            "Flow Duration": 5000000.0,
            "Total Fwd Packets": 1.0,
            "Total Backward Packets": 1.0,
            "Flow Packets/s": 100000.0,
            "Flow Bytes/s": 1000.0
        }
        is_real_bad, reason = self.fs.check_physical_consistency(bad_vec)
        self.assertFalse(is_real_bad)
        self.assertIn("contradicts", reason)


class TestModelPipeline(unittest.TestCase):
    def setUp(self):
        self.fs = FeatureService()
        self.ms = ModelService(self.fs)
        self.explainer = ExplainerService(self.ms, self.fs)
        self.profiles = ProfileService()

    def test_model_loaded(self):
        """Verify calibrated model and label encoder load successfully."""
        self.assertTrue(self.ms.is_loaded)
        expected_classes = [
            'BENIGN', 'SYN Flood', 'UDP Flood', 'Reflection DNS/NTP',
            'Slowloris', 'Slowhttptest', 'Hulk/GoldenEye'
        ]
        for c in expected_classes:
            self.assertIn(c, self.ms.classes)

    def test_benign_prediction(self):
        """Verify benign profile classifies as BENIGN with high confidence."""
        benign_vec = self.profiles.get_by_name("benign")
        res = self.ms.predict(benign_vec)
        self.assertEqual(res["label"], "BENIGN")
        self.assertGreater(res["confidence"], 0.80)
        self.assertIn("BENIGN", res["probabilities"])

    def test_syn_flood_prediction(self):
        """Verify SYN Flood preset classifies as SYN Flood."""
        syn_vec = self.profiles.get_by_name("syn_flood")
        res = self.ms.predict(syn_vec)
        self.assertEqual(res["label"], "SYN Flood")
        self.assertGreater(res["confidence"], 0.75)

    def test_udp_flood_prediction(self):
        """Verify UDP Flood preset classifies as UDP Flood."""
        udp_vec = self.profiles.get_by_name("udp_flood")
        res = self.ms.predict(udp_vec)
        self.assertEqual(res["label"], "UDP Flood")
        self.assertGreater(res["confidence"], 0.75)

    def test_slowloris_prediction(self):
        """Verify Slowloris preset classifies as Slowloris."""
        slow_vec = self.profiles.get_by_name("slowloris")
        res = self.ms.predict(slow_vec)
        self.assertEqual(res["label"], "Slowloris")
        self.assertGreater(res["confidence"], 0.70)

    def test_explain_attributions(self):
        """Verify 'Why this verdict' attribution returns top 8 driving features."""
        syn_vec = self.profiles.get_by_name("syn_flood")
        verdict = self.ms.predict(syn_vec)
        explain_res = self.explainer.explain(syn_vec, verdict)
        self.assertIsInstance(explain_res, list)
        self.assertLessEqual(len(explain_res), 8)
        self.assertGreater(len(explain_res), 0)
        
        # Verify first driving feature has positive contribution
        top_f = explain_res[0]
        self.assertIn("feature", top_f)
        self.assertIn("contribution", top_f)

    def test_decision_boundary_calculation(self):
        """Verify decision boundary helper sweeps and calculates threshold."""
        syn_vec = self.profiles.get_by_name("syn_flood")
        boundary = self.explainer.compute_decision_boundary(syn_vec, "SYN Flood")
        self.assertIn("feature", boundary)
        self.assertIn("current_value", boundary)
        self.assertIn("explanation", boundary)


if __name__ == "__main__":
    unittest.main()
