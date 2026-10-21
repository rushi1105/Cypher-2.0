"""Load and run the CIC-IDS2017 flow-level models."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_DIR = ROOT / "ml" / "artifacts"


class FlowPredictor:
    def __init__(self, artifact_dir: Optional[Path] = None) -> None:
        self.artifact_dir = Path(
            os.getenv("CYPHER_ML_ARTIFACT_DIR", str(DEFAULT_ARTIFACT_DIR))
        )
        if artifact_dir is not None:
            self.artifact_dir = Path(artifact_dir)

        self._binary = None
        self._multiclass = None
        self._anomaly = None
        self._loaded = False
        self._load_error: Optional[str] = None
        self.feature_names: list[str] = []
        self.threshold = 0.5

    def load(self) -> bool:
        if self._loaded:
            return True
        try:
            binary_path = self.artifact_dir / "binary_threat_classifier.joblib"
            multiclass_path = self.artifact_dir / "multiclass_attack_classifier.joblib"
            anomaly_path = self.artifact_dir / "flow_anomaly_detector.joblib"

            for path in (binary_path, multiclass_path, anomaly_path):
                if not path.exists():
                    raise FileNotFoundError(f"Missing model artifact: {path}")

            logger.info("Loading flow binary classifier …")
            self._binary = joblib.load(binary_path)
            logger.info("Loading flow multi-class classifier …")
            self._multiclass = joblib.load(multiclass_path)
            logger.info("Loading flow anomaly detector …")
            self._anomaly = joblib.load(anomaly_path)

            self.feature_names = list(self._binary["feature_names"])
            self.threshold = float(self._binary.get("threshold", 0.5))
            self._loaded = True
            logger.info("Flow models loaded successfully")
            return True
        except Exception as exc:
            self._load_error = str(exc)
            logger.error("Failed to load flow models: %s", exc)
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def _vector(self, features: dict) -> np.ndarray:
        return np.array(
            [[float(features.get(name, 0.0)) for name in self.feature_names]],
            dtype=np.float32,
        )

    def predict(self, features: dict) -> dict:
        if not self._loaded:
            return {
                "label": "Unknown",
                "attack_probability": 0.0,
                "is_threat": False,
                "category": "Unknown",
                "category_confidence": 0.0,
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "model_active": False,
                "threshold": self.threshold,
            }

        try:
            vector = self._vector(features)
            binary_model = self._binary["model"]
            classes = list(self._binary.get("classes", ["Normal", "Attack"]))
            probabilities = binary_model.predict_proba(vector)[0]
            attack_index = classes.index("Attack") if "Attack" in classes else 1
            attack_probability = float(probabilities[attack_index])
            is_threat = attack_probability >= self.threshold

            category = "Unknown"
            category_confidence = 0.0
            if self._multiclass is not None:
                multi_model = self._multiclass["model"]
                category = str(multi_model.predict(vector)[0])
                multi_probabilities = multi_model.predict_proba(vector)[0]
                category_confidence = float(np.max(multi_probabilities))

            anomaly_score = 0.0
            is_anomaly = False
            if self._anomaly is not None:
                anomaly_model = self._anomaly["model"]
                anomaly_score = float(-anomaly_model.score_samples(vector)[0])
                is_anomaly = bool(anomaly_model.predict(vector)[0] == -1)

            return {
                "label": "Attack" if is_threat else "Normal",
                "attack_probability": round(attack_probability, 4),
                "is_threat": is_threat,
                "category": category,
                "category_confidence": round(category_confidence, 4),
                "anomaly_score": round(anomaly_score, 4),
                "is_anomaly": is_anomaly,
                "model_active": True,
                "threshold": self.threshold,
            }
        except Exception as exc:
            logger.error("Flow prediction error: %s", exc)
            return {
                "label": "Unknown",
                "attack_probability": 0.0,
                "is_threat": False,
                "category": "Unknown",
                "category_confidence": 0.0,
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "model_active": False,
                "threshold": self.threshold,
                "error": str(exc),
            }


flow_predictor = FlowPredictor()
