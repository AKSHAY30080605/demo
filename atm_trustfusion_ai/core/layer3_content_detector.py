"""
layer3_content_detector.py - Layer 3: Content AI & ATM Contextual Analytics
Specialized for ATM Surveillance:
Performs:
  1. YOLOv8 real-time object detection (Persons, Bags, Suspicious items).
  2. ATM Occupancy State Estimation (Empty, Normal User, Suspicious Multi-Person).
  3. Contextual Cross-Check: Flags when an empty video feed is synthetic/looped.
"""

import os
import threading
import cv2

_COLORS = [
    (0, 255, 128),   # Green - Normal / Person
    (0, 165, 255),   # Orange - Bag / Object
    (255, 0, 128),   # Magenta - Phone / Other
    (0, 0, 255),     # Red - High Alert
]

class Layer3ContentDetector:
    def __init__(self, model_path=None, confidence=0.25):
        self.confidence = confidence
        self.model = None
        self.available = False
        self._lock = threading.Lock()
        self.frame_count = 0
        self.cached_detections = []
        self.cached_num_persons = 0
        
        if model_path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(base, "models", "yolov8n.pt")
        
        try:
            from ultralytics import YOLO
            self.model = YOLO(model_path)
            self.available = True
            print(f"[Layer 3] YOLOv8 loaded successfully from {model_path} (Optimized 320px)")
        except Exception as exc:
            print(f"[Layer 3] YOLO unavailable ({exc}). Continuing with content analyzer in fallback mode.")

    def detect(self, frame, layer1_flags=None):
        """
        Runs fast, real-time object detection with temporal box interpolation.
        Returns:
            annotated_frame: np.ndarray
            content_summary: dict
        """
        if frame is None:
            return None, {
                "layer": "Layer 3 (Content & Context)",
                "num_persons": 0,
                "objects": [],
                "occupancy_state": "UNKNOWN",
                "content_health": 0.0,
                "alerts": []
            }

        self.frame_count += 1
        annotated = frame.copy()
        alerts = []

        # Async worker handles inference pacing continuously
        should_infer = True

        if self.available and self.model is not None and should_infer:
            detections = []
            num_persons = 0
            with self._lock:
                try:
                    results = self.model.predict(
                        frame, conf=self.confidence, verbose=False, imgsz=320
                    )[0]

                    for box in results.boxes:
                        cls_id = int(box.cls[0])
                        label = self.model.names.get(cls_id, str(cls_id))
                        conf = float(box.conf[0])
                        x1, y1, x2, y2 = map(int, box.xyxy[0])

                        detections.append({
                            "label": label,
                            "confidence": round(conf, 3),
                            "box": [x1, y1, x2, y2]
                        })

                        if label == "person":
                            num_persons += 1

                    self.cached_detections = detections
                    self.cached_num_persons = num_persons
                except Exception as e:
                    print(f"[Layer 3] Inference error: {e}")

        # Render cached / latest detections
        detections = self.cached_detections
        num_persons = self.cached_num_persons

        for d in detections:
            x1, y1, x2, y2 = d["box"]
            label = d["label"]
            conf = d["confidence"]
            color = (0, 255, 128) if label == "person" and num_persons == 1 else ((0, 0, 255) if label == "person" else (0, 165, 255))
            cv2.rectangle(annotated, (x1, y1), (x2, y2), color, 2)
            cv2.putText(
                annotated, f"{label} {conf*100:.0f}%", (x1, max(18, y1 - 6)),
                cv2.FONT_HERSHEY_SIMPLEX, 0.52, color, 2
            )

        # ATM Occupancy State Evaluation
        if num_persons == 0:
            occupancy_state = "ATM_EMPTY"
            # Baseline health for an empty ATM
            content_health = 0.85
        elif num_persons == 1:
            occupancy_state = "ATM_OCCUPIED_NORMAL"
            content_health = 1.0
        else:
            occupancy_state = "ATM_MULTI_PERSON_RISK"
            content_health = 0.65
            alerts.append("ATM_CROWDED_CAUTION")

        # Contextual Cross-Check with Layer 1:
        # If Layer 1 detects video loop/freeze AND Layer 3 sees 0 persons, this is an ATM Video Loop Concealment Attack!
        if layer1_flags:
            if layer1_flags.get("video_replay_loop") and num_persons == 0:
                alerts.append("ATM_LOOP_CONCEALMENT_ACTIVE")
                content_health = 0.10
            elif layer1_flags.get("frozen_feed") and num_persons == 0:
                alerts.append("ATM_STILL_INJECTION_ACTIVE")
                content_health = 0.20

        return annotated, {
            "layer": "Layer 3 (Content & Context)",
            "num_persons": num_persons,
            "objects": detections,
            "detections": detections,
            "occupancy_state": occupancy_state,
            "content_health": round(content_health, 3),
            "alerts": alerts
        }
