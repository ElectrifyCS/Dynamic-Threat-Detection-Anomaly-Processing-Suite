"""
Robust (median/MAD) baseline and anomaly scoring.

AdaptiveThreshold assumes roughly-Gaussian behavior. That's fine most
of the time, but mean/std has a breakdown point of ~0%: a single
extreme reading can drag the mean and inflate the variance enough to
mask the next anomaly — which is exactly the moment a sustained,
low-and-slow attack would want that to happen.

RobustThreshold replaces mean/variance with median and MAD (median
absolute deviation), which have a ~50% breakdown point: up to half the
window can be arbitrary outliers before the estimate itself is
corrupted.

Trade-off: there's no O(1)-memory closed-form streaming median, so
this keeps a bounded sliding window (deque) rather than being a true
streaming estimator like AdaptiveThreshold. Fine for the window sizes
detectors actually need (tens to low hundreds of samples) — just
worth knowing this trades memory-boundedness for robustness, it isn't
a strict upgrade over AdaptiveThreshold in every respect.
"""

from collections import deque
from dataclasses import dataclass, field
import statistics

from .signal_smoother import SignalSmoother
from .anomaly_engine import AnomalyResult, z_to_score

# Scales MAD to be a consistent estimator of standard deviation *for
# normally distributed data* (1 / Phi^-1(3/4)). Doing this means
# `sensitivity` here means the same thing it does in AdaptiveThreshold:
# sensitivity=3.0 ≈ "3 robust standard deviations out", so the two
# classes stay drop-in comparable.
_MAD_TO_STD = 1.4826


@dataclass
class RobustThreshold:
    sensitivity: float = 3.0
    min_samples: int = 30
    window_size: int = 200
    min_mad_floor: float = 0.05

    def __post_init__(self):
        self._window: deque = deque(maxlen=self.window_size)

    def modified_z_score(self, value: float) -> float:
        """
        Modified z-score using median/MAD instead of mean/std.
        Undefined with fewer than 2 points in the window; callers
        should gate on min_samples the same way AdaptiveThreshold does.
        """
        window = list(self._window)
        med = statistics.median(window)
        mad = statistics.median(abs(x - med) for x in window)
        robust_std = max(mad * _MAD_TO_STD, self.min_mad_floor)
        return (value - med) / robust_std

    def evaluate_and_update(self, value: float) -> tuple[bool, float]:
        """
        Check value against the *current* window, then fold it in.
        Same update-after-check ordering as AdaptiveThreshold, for the
        same reason: don't let the anomalous point dilute its own score.
        """
        has_baseline = len(self._window) >= self.min_samples
        if has_baseline:
            z = self.modified_z_score(value)
            flagged = abs(z) >= self.sensitivity
        else:
            z = 0.0
            flagged = False

        self._window.append(value)
        return flagged, z

    @property
    def baseline(self) -> tuple[float, float]:
        """(median, robust_std) — mirrors AdaptiveThreshold.baseline."""
        if len(self._window) < 2:
            return (0.0, 0.0)
        window = list(self._window)
        med = statistics.median(window)
        mad = statistics.median(abs(x - med) for x in window)
        return med, mad * _MAD_TO_STD

    @property
    def mean(self) -> float:
        """Alias for the median, so RobustThreshold can substitute for
        AdaptiveThreshold anywhere that reads `.mean` for context."""
        return self.baseline[0]


@dataclass
class RobustAnomalyEngine:
    """
    Drop-in alternative to AnomalyEngine for entities whose telemetry
    is bursty or heavy-tailed rather than roughly-normal (e.g. file
    modification counts, which tend to sit near 0 with rare large
    bursts, rather than clustering around a mean).

    Same shape as AnomalyEngine on purpose — swap one for the other
    inside any detector without touching the detector's own logic.
    """
    sensitivity: float = 3.0
    min_samples: int = 30
    window_size: int = 200
    min_mad_floor: float = 0.05
    process_variance: float = 1e-3
    measurement_variance: float = 1e-1

    def __post_init__(self):
        self._smoother = SignalSmoother(
            process_variance=self.process_variance,
            measurement_variance=self.measurement_variance,
        )
        self._threshold = RobustThreshold(
            sensitivity=self.sensitivity,
            min_samples=self.min_samples,
            window_size=self.window_size,
            min_mad_floor=self.min_mad_floor,
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
        return self._threshold.mean

    @property
    def baseline(self) -> tuple[float, float]:
        return self._threshold.baseline
