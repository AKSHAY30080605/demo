"""
layer1_feed_integrity.py - Layer 1: Physical / Temporal Feed Dynamics Analyzer
Specialized for ATM Surveillance:
Detects:
  1. VIDEO_REPLAY_LOOP: Detects looped footage of an empty ATM room via cyclic temporal hashing.
  2. FROZEN_FEED: Detects still image injection or frozen stream (thermal noise check).
  3. BLACK_FRAME: Detects lens obstruction, spray paint, or signal cut.
  4. FEED_LOSS: Detects hardware disconnect or network cable severing.
"""

import time
from collections import deque
import cv2
import numpy as np

class Layer1FeedIntegrity:
    def __init__(
        self,
        freeze_diff=0.08,           # Calibrated for Pi sensor noise floor (~0.15 - 0.28)
        black_threshold=12.0,
        loss_seconds=3.0,
        loop_history_len=500,       # ~20 seconds history
        min_loop_period=28,         # minimum ~1.1 second loop cycle
        loop_match_threshold=1.5,   # normalized L1 difference threshold
        consecutive_matches_needed=5 # consecutive frames verifying identical period
    ):
        self.freeze_diff = freeze_diff
        self.black_threshold = black_threshold
        self.loss_seconds = loss_seconds
        
        self.loop_history_len = loop_history_len
        self.min_loop_period = min_loop_period
        self.loop_match_threshold = loop_match_threshold
        self.consecutive_matches_needed = consecutive_matches_needed
        
        # State
        self.last_frame_time = 0.0
        self._prev_small = None
        self._frozen_count = 0
        
        # Circular buffer of downscaled 16x16 frame hashes
        # Each entry: (frame_idx, timestamp, 16x16 float32 matrix)
        self.hash_history = deque(maxlen=self.loop_history_len)
        self.frame_idx = 0
        
        # Tracking loop sequence candidate
        self.detected_loop_period = None
        self.loop_streak = 0
        self.loop_detected = False

    @staticmethod
    def _extract_signature(frame):
        """Downscale to 16x16 grayscale float array for fast, robust temporal matching."""
        if frame.ndim == 3:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        else:
            gray = frame
        resized = cv2.resize(gray, (16, 16), interpolation=cv2.INTER_AREA)
        return resized.astype(np.float32)

    def update(self, frame):
        """
        Analyzes the frame and returns integrity metrics.
        Returns:
            dict containing flags, scores, feed_health (0.0 - 1.0), alerts
        """
        now = time.time()
        self.frame_idx += 1
        
        flags = {
            "feed_loss": False,
            "black_frame": False,
            "frozen_feed": False,
            "video_replay_loop": False
        }
        scores = {
            "feed_loss": 0.0,
            "black_frame": 0.0,
            "frozen_feed": 0.0,
            "video_replay_loop": 0.0
        }
        details = {
            "brightness": 0.0,
            "temporal_delta": 0.0,
            "loop_streak": 0,
            "detected_loop_period_frames": None
        }

        # 1. Feed Loss Check
        if frame is None:
            age = (now - self.last_frame_time) if self.last_frame_time else (self.loss_seconds + 1)
            if age >= self.loss_seconds:
                flags["feed_loss"] = True
                scores["feed_loss"] = 1.0
            return self._finalize(flags, scores, details)

        self.last_frame_time = now

        # 2. Black Frame Check (Lens covered, spray painted, or sensor detached)
        brightness = float(frame.mean())
        details["brightness"] = round(brightness, 2)
        if brightness < self.black_threshold:
            flags["black_frame"] = True
            # Real camera darkness has thermal noise ~18-35. Below 12 is synthetic or covered.
            severity = min(1.0, (self.black_threshold - brightness) / self.black_threshold + 0.4)
            scores["black_frame"] = round(severity, 3)

        # 3. Frozen Feed / Still Image Injection Check
        sig = self._extract_signature(frame)
        if self._prev_small is not None:
            delta = float(np.abs(sig - self._prev_small).mean())
            details["temporal_delta"] = round(delta, 3)
            if delta < self.freeze_diff:
                self._frozen_count += 1
            else:
                self._frozen_count = max(0, self._frozen_count - 5)

            if self._frozen_count >= 15:
                flags["frozen_feed"] = True
                scores["frozen_feed"] = min(1.0, round(self._frozen_count / 30.0, 3))
        self._prev_small = sig

        # 4. ATM Video Replay Loop Detector (Cyclic Temporal Hash Autocorrelation)
        # Search backwards in history for matching frame signature
        matched_period = None
        min_dist = float("inf")

        # Only check history older than min_loop_period
        for past_idx, past_time, past_sig in self.hash_history:
            frame_gap = self.frame_idx - past_idx
            if frame_gap < self.min_loop_period:
                continue

            # Normalized Mean Absolute Difference between 16x16 signatures
            diff = float(np.abs(sig - past_sig).mean())
            if diff < self.loop_match_threshold and diff < min_dist:
                min_dist = diff
                matched_period = frame_gap

        if matched_period is not None:
            if self.detected_loop_period is not None and abs(matched_period - self.detected_loop_period) <= 2:
                self.loop_streak += 1
            else:
                self.detected_loop_period = matched_period
                self.loop_streak = 1
        else:
            self.loop_streak = max(0, self.loop_streak - 1)
            if self.loop_streak == 0:
                self.detected_loop_period = None

        details["loop_streak"] = self.loop_streak
        details["detected_loop_period_frames"] = self.detected_loop_period

        if self.loop_streak >= self.consecutive_matches_needed:
            flags["video_replay_loop"] = True
            self.loop_detected = True
            # High severity for replay attacks in banking/ATM surveillance
            loop_sev = min(1.0, 0.70 + (self.loop_streak / 25.0) * 0.30)
            scores["video_replay_loop"] = round(loop_sev, 3)
        else:
            self.loop_detected = False

        # Add current frame signature to circular history
        self.hash_history.append((self.frame_idx, now, sig))

        return self._finalize(flags, scores, details)

    def reset(self):
        """Resets all integrity state to clean 100% genuine feed."""
        self._prev_small = None
        self._frozen_count = 0
        self.loop_streak = 0
        self.detected_loop_period = None
        self.loop_detected = False
        self.hash_history.clear()
        self.last_frame_time = time.time()
        self.last_result = {
            "layer": "Layer 1 (Feed Integrity)",
            "flags": {
                "feed_loss": False,
                "black_frame": False,
                "frozen_feed": False,
                "video_replay_loop": False
            },
            "scores": {
                "feed_loss": 0.0,
                "black_frame": 0.0,
                "frozen_feed": 0.0,
                "video_replay_loop": 0.0
            },
            "details": {
                "brightness": 128.0,
                "temporal_delta": 0.25,
                "loop_streak": 0,
                "detected_loop_period_frames": None
            },
            "feed_health": 1.0,
            "alerts": []
        }

    def _finalize(self, flags, scores, details):
        max_penalty = max(scores.values()) if scores else 0.0
        feed_health = round(max(0.0, 1.0 - max_penalty), 3)
        
        alerts = [k.upper() for k, v in flags.items() if v]
        res = {
            "layer": "Layer 1 (Feed Integrity)",
            "flags": flags,
            "scores": scores,
            "details": details,
            "feed_health": feed_health,
            "alerts": alerts
        }
        self._last_result = res
        return res

    def get_last_result(self):
        if hasattr(self, "_last_result") and self._last_result:
            return dict(self._last_result)
        return self.update(None)
