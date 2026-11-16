"""
profiles.py - Manages attack preset profiles for one-click demonstration buttons.
"""

import os
import json
from typing import Dict, Any
from backend.config import PROFILES_PATH

PRESET_NAME_MAPPINGS = {
    "syn_flood": "SYN Flood",
    "udp_flood": "UDP Flood",
    "reflection": "Reflection DNS/NTP",
    "slowloris": "Slowloris",
    "slowhttptest": "Slowhttptest",
    "hulk_goldeneye": "Hulk/GoldenEye",
    "benign": "BENIGN"
}

class ProfileService:
    def __init__(self, profiles_path: str = PROFILES_PATH):
        self.profiles_path = profiles_path
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.load_profiles()

    def load_profiles(self):
        if os.path.exists(self.profiles_path):
            with open(self.profiles_path, "r", encoding="utf-8") as f:
                self.profiles = json.load(f)
            print(f"[ProfileService] Loaded profiles: {list(self.profiles.keys())}")
        else:
            print(f"[ProfileService] Profiles file not found at {self.profiles_path}")

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        return self.profiles

    def get_by_name(self, name: str) -> Dict[str, Any]:
        mapped = PRESET_NAME_MAPPINGS.get(name.lower(), name)
        return self.profiles.get(mapped, self.profiles.get("BENIGN", {}))
