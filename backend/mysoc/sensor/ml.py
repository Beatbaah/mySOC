"""Anomaly scoring with an Isolation Forest trained on recent flows.

Trained on this network's own traffic, refreshed periodically, and
reported at low severity: an outlier isn't an attack by itself, but next
to other alerts on the same host it's useful context.
"""

import math
import random
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from .detection.detectors import Finding, RuleConfig
from .flows import FlowRecord
from .netctx import NetContext


def features(f: FlowRecord, net: NetContext) -> list[float]:
    duration = max((f.end - f.start).total_seconds(), 0.0)
    port = f.dst_port
    return [
        math.log1p(f.bytes),
        math.log1p(f.packets),
        math.log1p(duration),
        math.log1p(f.bytes / max(f.packets, 1)),
        0.0 if port < 1024 else 1.0 if port < 49152 else 2.0,
        1.0 if f.protocol == "TCP" else 0.0,
        1.0 if f.protocol == "UDP" else 0.0,
        1.0 if net.internal(f.src_ip) else 0.0,
        1.0 if net.internal(f.dst_ip) else 0.0,
    ]


class AnomalyModel:
    SAMPLE_SIZE = 5000
    RETRAIN_EVERY = timedelta(minutes=30)

    def __init__(self, net: NetContext, seed: int = 7):
        self.net = net
        self.rng = random.Random(seed)
        self.sample: list[list[float]] = []
        self.seen = 0
        self.model: IsolationForest | None = None
        self.trained_at: datetime | None = None
        self.anomalies = 0

    def stats(self) -> dict:
        return {
            "trained": self.model is not None,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "training_flows": len(self.sample),
            "anomalies": self.anomalies,
        }

    def process(self, flows: list[FlowRecord], rule: RuleConfig | None) -> list[Finding]:
        """Score a batch of flows at once (one model call per batch)."""
        if not flows:
            return []
        xs = [features(f, self.net) for f in flows]
        for x in xs:
            # Reservoir sampling: a uniform sample of everything seen so far.
            self.seen += 1
            if len(self.sample) < self.SAMPLE_SIZE:
                self.sample.append(x)
            else:
                j = self.rng.randrange(self.seen)
                if j < self.SAMPLE_SIZE:
                    self.sample[j] = x
        if rule is None or not rule.enabled:
            return []
        last = flows[-1].end
        if (self.model is None and len(self.sample) >= rule.params.get("min_training_flows", 2000)) or (
            self.trained_at and last - self.trained_at > self.RETRAIN_EVERY
        ):
            self._train(last)
        if self.model is None:
            return []
        threshold = rule.params.get("score_threshold", -0.2)
        scores = self.model.decision_function(np.array(xs))
        out = []
        for f, score in zip(flows, scores, strict=False):
            if score >= threshold:
                continue
            self.anomalies += 1
            out.append(Finding(
                rule.id, f"Unusual flow {f.src_ip} → {f.dst_ip}:{f.dst_port}",
                f"{f.protocol} flow of {f.packets:,} packets / {f.bytes:,} bytes over "
                f"{(f.end - f.start).total_seconds():.0f} s doesn't fit this network's normal traffic "
                f"(anomaly score {score:.2f}).",
                f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.src_country,
                evidence={"anomaly_score": round(float(score), 3), "bytes": f.bytes, "packets": f.packets},
                dedup_fields=("src_ip", "dst_ip"),
            ))
        return out

    def _train(self, now: datetime) -> None:
        self.model = IsolationForest(n_estimators=100, contamination="auto", random_state=7)
        self.model.fit(np.array(self.sample))
        self.trained_at = now
