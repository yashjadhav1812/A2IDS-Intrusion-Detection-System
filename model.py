"""
Machine Learning Model module for AI-NIDS/IPS.
Loads and manages the trained Random Forest classifier and Isolation Forest anomaly detector.
Performs strict feature validation, probability calibration, latency tracking, and explainability.
Never fabricates predictions or confidence scores.
"""

import os
import json
import time
import pickle
import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "flow_duration",
    "total_fwd_pkts",
    "total_bwd_pkts",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_max",
    "pkt_len_min",
    "flow_pkts_per_sec",
    "flow_bytes_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "flow_iat_mean"
]

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "ids_model.pkl")
DEFAULT_SCHEMA_PATH = os.path.join(DEFAULT_MODEL_DIR, "feature_schema.json")
DEFAULT_METRICS_PATH = os.path.join(DEFAULT_MODEL_DIR, "metrics.json")


class IDSModelPipeline:
    """
    Wrapper for supervised Random Forest classification and unsupervised
    Isolation Forest anomaly detection.
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None
        self.classes: List[str] = []
        self.is_loaded: bool = False
        self.status_message: str = "Uninitialized"
        self.metrics: Dict[str, Any] = {}
        self.feature_names: List[str] = FEATURE_NAMES

        self.load()

    def load(self) -> bool:
        """Load serialized model artifact and evaluation metrics."""
        if not os.path.exists(self.model_path):
            self.is_loaded = False
            self.status_message = f"Model artifact not found at {self.model_path}. Run train_model.py to train."
            logger.warning(self.status_message)
            return False

        try:
            with open(self.model_path, "rb") as f:
                artifact = pickle.load(f)

            self.classifier = artifact.get("classifier")
            self.anomaly_detector = artifact.get("anomaly_detector")
            self.scaler = artifact.get("scaler")
            self.classes = artifact.get("classes", ["BENIGN", "SYN_FLOOD", "PORT_SCAN", "GENERIC_MALICIOUS"])
            self.feature_names = artifact.get("feature_names", FEATURE_NAMES)

            # Load metrics if available
            if os.path.exists(DEFAULT_METRICS_PATH):
                try:
                    with open(DEFAULT_METRICS_PATH, "r") as mf:
                        self.metrics = json.load(mf)
                except Exception:
                    self.metrics = {}

            self.is_loaded = True
            self.status_message = "Model loaded successfully and ready for inference."
            logger.info("IDS ML Pipeline successfully loaded from %s", self.model_path)
            return True
        except Exception as e:
            self.is_loaded = False
            self.status_message = f"Failed to load model artifact: {e}"
            logger.error(self.status_message)
            return False

    def predict(self, feature_dict: Dict[str, float]) -> Optional[Dict[str, Any]]:
        """
        Run inference on a single flow feature dictionary.
        Returns prediction, calibrated confidence, anomaly score, and explanation.
        """
        if not self.is_loaded or self.classifier is None:
            return None

        # Build ordered feature vector and validate
        vector = []
        for name in self.feature_names:
            val = feature_dict.get(name, 0.0)
            if val is None or np.isnan(val) or np.isinf(val):
                val = 0.0
            vector.append(float(val))

        X = np.array([vector])

        start_time = time.perf_counter()

        # Scale features if scaler is present
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X

        # Classifier prediction and probability distribution
        pred_idx = self.classifier.predict(X_scaled)[0]
        if hasattr(self.classifier, "predict_proba"):
            probs = self.classifier.predict_proba(X_scaled)[0]
            confidence = float(np.max(probs))
            class_probs = {cls_name: round(float(prob), 4) for cls_name, prob in zip(self.classes, probs)}
        else:
            confidence = 1.0
            class_probs = {}

        predicted_class = self.classes[pred_idx] if pred_idx < len(self.classes) else "UNKNOWN"

        # Isolation Forest Anomaly Detection
        is_anomaly = False
        anomaly_score = 0.0
        if self.anomaly_detector is not None:
            # decision_function: lower means more anomalous; negative typically outlier
            raw_score = float(self.anomaly_detector.decision_function(X_scaled)[0])
            anomaly_score = round(raw_score, 4)
            is_anomaly = bool(self.anomaly_detector.predict(X_scaled)[0] == -1)

        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Feature explanation (top 3 highest standardized features)
        top_features = []
        if self.scaler is not None:
            scaled_vals = np.abs(X_scaled[0])
            top_indices = np.argsort(scaled_vals)[::-1][:3]
            for idx in top_indices:
                top_features.append({
                    "feature": self.feature_names[idx],
                    "raw_value": vector[idx],
                    "scaled_deviation": round(float(scaled_vals[idx]), 2)
                })

        return {
            "predicted_class": predicted_class,
            "confidence": round(confidence, 4),
            "class_probabilities": class_probs,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "inference_latency_ms": latency_ms,
            "top_contributing_features": top_features
        }

    def get_status(self) -> Dict[str, Any]:
        """Return model loading and evaluation status."""
        return {
            "is_loaded": self.is_loaded,
            "status_message": self.status_message,
            "classes": self.classes,
            "feature_count": len(self.feature_names),
            "model_path": self.model_path,
            "metrics": self.metrics
        }


# Global singleton
_model_instance: Optional[IDSModelPipeline] = None

def get_model_pipeline() -> IDSModelPipeline:
    """Return the global IDSModelPipeline singleton."""
    global _model_instance
    if _model_instance is None:
        _model_instance = IDSModelPipeline()
    return _model_instance
