"""
live_source.py - Pluggable live stream source (CSV replay or live socket capture).
"""

import os
import time
import asyncio
import pandas as pd
from typing import Dict, Any, List
from backend.config import CSV_REPLAY_PATH, LIVE_SOURCE

class LiveSource:
    def __init__(self, mode: str = LIVE_SOURCE, csv_path: str = CSV_REPLAY_PATH):
        self.mode = mode
        self.csv_path = csv_path
        self.rows: List[Dict[str, float]] = []
        self.row_idx = 0
        self.frozen = False
        self.current_live: Dict[str, float] = {}
        self.load_data()

    def load_data(self):
        if os.path.exists(self.csv_path):
            df = pd.read_csv(self.csv_path)
            self.rows = df.to_dict(orient="records")
            if self.rows:
                self.current_live = dict(self.rows[0])
            print(f"[LiveSource] Loaded {len(self.rows)} replay rows from {self.csv_path}")
        else:
            print(f"[LiveSource] CSV not found at {self.csv_path}, initializing default baseline.")
            self.current_live = {
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
            }

    def set_freeze(self, is_frozen: bool):
        self.frozen = is_frozen

    def step(self) -> Dict[str, float]:
        """Steps forward by 1 row unless frozen."""
        if not self.frozen and self.rows:
            self.row_idx = (self.row_idx + 1) % len(self.rows)
            self.current_live = dict(self.rows[self.row_idx])
        return self.current_live

    def get_current(self) -> Dict[str, float]:
        return dict(self.current_live)
