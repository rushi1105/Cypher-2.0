"""
ml_predictor.py
---------------
Loads the two trained models from server/ml/ and exposes a single
predict(feature_dict) call that returns both the classifier result
and the anomaly detector score.

Models
------
  ml/threat_classifier.pkl  → sklearn RandomForestClassifier
  ml/anomaly_detector.pkl   → sklearn IsolationForest

Expected feature order (must match training order in upgrade_and_retrain.py):
  packet_count, avg_packet_size, tcp_count, udp_count,
  unique_ips, syn_count, tcp_ratio, syn_ratio,
  packet_size_std, avg_interarrival_time, unique_ports
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# ── Feature order must match training order exactly ────────────────────────────
FEATURE_ORDER = [
    "packet_count",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "unique_ips",
    "syn_count",
    "tcp_ratio",
    "syn_ratio",
    "packet_size_std",
    "avg_interarrival_time",
    "unique_ports",
]

# Confidence threshold: predictions below this are treated as "uncertain"
CONFIDENCE_THRESHOLD = 0.80

# ── Model directory ────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
ML_DIR = _HERE / "ml"
CLASSIFIER_PATH  = ML_DIR / "threat_classifier.pkl"
ANOMALY_PATH     = ML_DIR / "anomaly_detector.pkl"


class MLPredictor:
    """
    Singleton-style predictor that loads models once and exposes predict().
    """

    def __init__(self) -> None:
        self._classifier  = None
        self._anomaly_det = None
        self._loaded      = False
        self._load_error: Optional[str] = None

    # ── Loading ────────────────────────────────────────────────────────────────
    def load(self) -> bool:
        """
        Load both .pkl model files.
        Returns True on success, False if either model fails to load.
        Safe to call multiple times — re-loads only if not already loaded.
        """
        if self._loaded:
            return True

        try:
            if not CLASSIFIER_PATH.exists():
                raise FileNotFoundError(f"Missing: {CLASSIFIER_PATH}")
            if not ANOMALY_PATH.exists():
                raise FileNotFoundError(f"Missing: {ANOMALY_PATH}")

            logger.info("Loading threat_classifier.pkl …")
            self._classifier = joblib.load(CLASSIFIER_PATH)

            logger.info("Loading anomaly_detector.pkl …")
            self._anomaly_det = joblib.load(ANOMALY_PATH)

            self._loaded = True
            logger.info("✅  ML models loaded successfully")
            return True

        except Exception as exc:
            self._load_error = str(exc)
            logger.error("❌  Failed to load ML models: %s", exc)
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    # ── Feature vector ─────────────────────────────────────────────────────────
    def _build_feature_vector(self, feature_dict: dict) -> np.ndarray:
        """
        Convert a feature dict (from PacketWindowBuffer) into a numpy
        row array in the exact order FEATURE_ORDER.
        Missing keys default to 0.
        """
        row = [float(feature_dict.get(feat, 0.0)) for feat in FEATURE_ORDER]
        return np.array(row, dtype=np.float64).reshape(1, -1)

    # ── Prediction ─────────────────────────────────────────────────────────────
    def predict(self, feature_dict: dict) -> dict:
        """
        Run both models on the feature window and return a result dict:
        {
          "label":          "Normal" | "Attack" | "Unknown",
          "confidence":     float (0.0 – 1.0),
          "is_threat":      bool,
          "anomaly_score":  float  (lower = more anomalous),
          "is_anomaly":     bool,
          "model_active":   bool   (False if models not loaded)
        }
        """
        if not self._loaded:
            return {
                "label":         "Unknown",
                "confidence":    0.0,
                "is_threat":     False,
                "anomaly_score": 0.0,
                "is_anomaly":    False,
                "model_active":  False,
            }

        try:
            X = self._build_feature_vector(feature_dict)

            # ── Random Forest ──────────────────────────────────────────────────
            proba  = self._classifier.predict_proba(X)[0]   # [p_normal, p_attack]
            label_idx   = int(np.argmax(proba))
            confidence  = float(proba[label_idx])
            label       = "Attack" if label_idx == 1 else "Normal"

            # Apply confidence threshold: below threshold → "Normal" (reduce false positives)
            is_threat = (label == "Attack") and (confidence >= CONFIDENCE_THRESHOLD)

            # ── Isolation Forest ───────────────────────────────────────────────
            # score_samples returns negative values; more negative = more anomalous
            anomaly_score = float(self._anomaly_det.score_samples(X)[0])
            # IsolationForest.predict returns -1 for anomalies, +1 for normal
            iso_pred  = int(self._anomaly_det.predict(X)[0])
            is_anomaly = (iso_pred == -1)

            return {
                "label":         label,
                "confidence":    round(confidence, 4),
                "is_threat":     is_threat,
                "anomaly_score": round(anomaly_score, 4),
                "is_anomaly":    is_anomaly,
                "model_active":  True,
            }

        except Exception as exc:
            logger.error("ML prediction error: %s", exc)
            return {
                "label":         "Unknown",
                "confidence":    0.0,
                "is_threat":     False,
                "anomaly_score": 0.0,
                "is_anomaly":    False,
                "model_active":  False,
                "error":         str(exc),
            }


# ── Module-level singleton ─────────────────────────────────────────────────────
predictor = MLPredictor()
