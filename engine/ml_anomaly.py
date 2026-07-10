"""
engine/ml_anomaly.py — Isolation Forest based anomaly detection
"""

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import List, Optional

import numpy as np

import config
from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    log.warning("scikit-learn not installed — ML anomaly detection disabled")


@dataclass
class AnomalyResult:
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    protocol:   str
    length:     int
    score:      float   # raw anomaly score (more negative = more anomalous)
    is_anomaly: bool


def _extract_features(pkt) -> List[float]:
    """Convert a packet record into a numeric feature vector."""
    proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "GRE": 47}
    proto_num = proto_map.get(pkt.protocol, 0)

    # Encode IP last octet as crude locality signal
    def last_octet(ip: str) -> int:
        try:
            return int(ip.split(".")[-1])
        except Exception:
            return 0

    return [
        pkt.src_port,
        pkt.dst_port,
        proto_num,
        pkt.length,
        pkt.ttl,
        last_octet(pkt.src_ip),
        last_octet(pkt.dst_ip),
        1 if "S" in pkt.flags else 0,
        1 if "F" in pkt.flags else 0,
        1 if "R" in pkt.flags else 0,
    ]


class MLAnomalyDetector:
    """
    Online anomaly detector using Isolation Forest.
    Collects a sliding window of packet feature vectors and periodically
    retrains the model. Each new packet is scored against the current model.
    """

    def __init__(self):
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._training_buffer: deque = deque(maxlen=5000)
        self._callbacks = []
        self._lock = threading.Lock()
        self._last_train = 0.0
        self._trained = False
        self._anomaly_count = 0
        self._total_count = 0

    # ── Public API ──────────────────────────────────────────────────────────────

    def add_callback(self, fn) -> None:
        self._callbacks.append(fn)

    def process(self, pkt) -> Optional[AnomalyResult]:
        if not SKLEARN_AVAILABLE:
            return None

        features = _extract_features(pkt)
        self._training_buffer.append(features)
        self._total_count += 1

        # Retrain if needed
        now = time.time()
        if (now - self._last_train > config.ML_RETRAIN_INTERVAL_S and
                len(self._training_buffer) >= config.ML_MIN_SAMPLES):
            self._retrain()

        if not self._trained:
            return None

        result = self._score(pkt, features)
        if result.is_anomaly:
            self._anomaly_count += 1
            for cb in self._callbacks:
                try:
                    cb(result)
                except Exception as e:
                    log.debug("ML callback error: %s", e)
        return result

    def get_stats(self) -> dict:
        return {
            "trained":       self._trained,
            "total_packets": self._total_count,
            "anomalies":     self._anomaly_count,
            "buffer_size":   len(self._training_buffer),
            "last_train":    self._last_train,
        }

    def force_retrain(self) -> bool:
        return self._retrain()

    # ── Internal ────────────────────────────────────────────────────────────────

    def _retrain(self) -> bool:
        with self._lock:
            data = list(self._training_buffer)
        if len(data) < config.ML_MIN_SAMPLES:
            return False

        try:
            X = np.array(data, dtype=float)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=config.ML_N_ESTIMATORS,
                contamination=config.ML_CONTAMINATION,
                random_state=config.ML_RANDOM_STATE,
                n_jobs=-1,
            )
            model.fit(X_scaled)

            with self._lock:
                self._model = model
                self._scaler = scaler
                self._trained = True
                self._last_train = time.time()

            log.info("ML model retrained on %d samples", len(data))
            return True
        except Exception as e:
            log.error("ML retrain failed: %s", e)
            return False

    def _score(self, pkt, features: List[float]) -> AnomalyResult:
        with self._lock:
            model, scaler = self._model, self._scaler

        try:
            X = np.array([features], dtype=float)
            X_scaled = scaler.transform(X)
            score = model.score_samples(X_scaled)[0]
            prediction = model.predict(X_scaled)[0]  # -1 = anomaly
            is_anomaly = prediction == -1
        except Exception as e:
            log.debug("Scoring error: %s", e)
            score = 0.0
            is_anomaly = False

        return AnomalyResult(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol,
            length=pkt.length,
            score=float(score),
            is_anomaly=is_anomaly,
        )
