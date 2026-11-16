"""
config.py - Environment and application settings.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load from .env if present
env_file = BASE_DIR / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "model.joblib"))
SCALER_PATH = os.getenv("SCALER_PATH", str(BASE_DIR / "models" / "scaler.joblib"))
FEATURES_PATH = os.getenv("FEATURES_PATH", str(BASE_DIR / "models" / "feature_list.json"))
LABELS_PATH = os.getenv("LABELS_PATH", str(BASE_DIR / "models" / "label_encoder.joblib"))
PROFILES_PATH = os.getenv("PROFILES_PATH", str(BASE_DIR / "models" / "profiles.json"))
CSV_REPLAY_PATH = os.getenv("CSV_REPLAY_PATH", str(BASE_DIR / "data" / "sample_flows.csv"))
LIVE_SOURCE = os.getenv("LIVE_SOURCE", "replay")  # "replay" or "live"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
