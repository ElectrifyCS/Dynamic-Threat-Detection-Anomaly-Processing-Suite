"""
Adaptive mean/variance tracker with z-score anomaly flagging.

Two modes:
- stationary=True  → classic Welford online algorithm (stable baseline)
- stationary=False → EMA mean/variance (handles concept drift)

Includes:
- Zero-variance fix: entities with a legitimately constant baseline
  (e.g. rate always 0) can still be flagged on genuine deviation.
- Variance floor: prevents an artificially tight early estimate from
  producing false positives right after min_samples.
"""

from dataclasses import dataclass, field
import math


@dataclass
class AdaptiveThreshold:
    sensitivity: float = 3.0
    min_samples: int = 30
    stationary: bool = False
    decay: float = 0.05
    min_std_ratio: float = 0.2
    min_std_floor: float = 0.1

    _count: int = field(default=0, init=False)
    _mean: float = field(default=0.0, init=False)
    _m2: float = field(default=0.0, init=False)
    _variance: float = field(default=0.0, init=False)

    def z_score(self, value: float) -> float:
        std = self._variance ** 0.5
        if std == 0:
            if value == self._mean:
                return 0.0
            # Zero-variance baseline (e.g. process that never touched
            # credential files). Returning 0 would permanently blind the
            # detector. Return a large finite, sign-matched z instead.
            return math.copysign(self.sensitivity * 10, value - self._mean)

        # Floor std so a lucky-tight early window doesn't inflate z-scores.
        min_std = max(self.min_std_floor, abs(self._mean) * self.min_std_ratio)
        effective_std = max(std, min_std)
        return (value - self._mean) / effective_std

    def evaluate_and_update(self, value: float) -> tuple[bool, float]:
        """
        Check value against the *current* baseline, then fold it in.
        Order matters: update-after-check keeps the anomalous observation
        from diluting its own z-score.
        """
        has_baseline = self._count >= self.min_samples
        if has_baseline:
            z = self.z_score(value)
            flagged = abs(z) >= self.sensitivity
        else:
            z = 0.0
            flagged = False

        self._count += 1
        if self.stationary:
            delta = value - self._mean
            self._mean += delta / self._count
            delta2 = value - self._mean
            self._m2 += delta * delta2
            self._variance = self._m2 / self._count if self._count > 1 else 0.0
        else:
            if self._count == 1:
                self._mean = value
                self._variance = 0.0
            else:
                delta = value - self._mean
                self._mean += self.decay * delta
                self._variance = (1 - self.decay) * (
                    self._variance + self.decay * delta * delta
                )

        return flagged, z

    @property
    def baseline(self) -> tuple[float, float]:
        """(mean, std) — useful for reviewer context."""
        return self._mean, self._variance ** 0.5

    @property
    def mean(self) -> float:
        return self._mean
