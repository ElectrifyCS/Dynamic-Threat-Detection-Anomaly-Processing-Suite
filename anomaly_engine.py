"""
Shared statistical core.

Takes any stream of numbers, smooths it (Kalman), tracks an adaptive
baseline, and returns a bounded anomaly score in [0, 1] plus a flag.
Contains NO domain knowledge — that lives in the detectors.
"""

import math
from dataclasses import dataclass

from .signal_smoother import SignalSmoother
from .adaptive_threshold import AdaptiveThreshold


def z_to_score(z: float, steepness: float = 0.5) -> float:
    """Map |z| → [0, 1] via a shifted sigmoid (z=0 → ~0, large |z| → ~1)."""
    return 2 / (1 + math.exp(-steepness * abs(z))) - 1


@dataclass
class AnomalyResult:
    raw_value: float
    smoothed_value: float
    z_score: float
    anomaly_score: float  # 0–1
    is_anomaly: bool


@dataclass
class AnomalyEngine:
    sensitivity: float = 3.0
    min_samples: int = 30
    stationary: bool = False
    decay: float = 0.05
    process_variance: float = 1e-3
    measurement_variance: float = 1e-1
    # Configurable because rate-like signals and bounded 0–1 signals
    # (entropy) need different floors.
    min_std_ratio: float = 0.2
    min_std_floor: float = 0.1

    def __post_init__(self):
        self._smoother = SignalSmoother(
            process_variance=self.process_variance,
            measurement_variance=self.measurement_variance,
        )
        self._threshold = AdaptiveThreshold(
            sensitivity=self.sensitivity,
            min_samples=self.min_samples,
            stationary=self.stationary,
            decay=self.decay,
            min_std_ratio=self.min_std_ratio,
            min_std_floor=self.min_std_floor,
        )

    def process(self, raw_value: float) -> AnomalyResult:
        smoothed = self._smoother.update(raw_value)
        flagged, z = self._threshold.evaluate_and_update(smoothed)
        score = z_to_score(z)
        return AnomalyResult(
            raw_value=raw_value,
            smoothed_value=smoothed,
            z_score=z,
            anomaly_score=score,
            is_anomaly=flagged,
        )

    @property
    def baseline_mean(self) -> float:
        """Current baseline mean — safe for detectors to put in context."""
        return self._threshold.mean

    @property
    def baseline(self) -> tuple[float, float]:
        """(mean, std)."""
        return self._threshold.baseline
