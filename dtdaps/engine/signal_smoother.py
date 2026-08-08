"""
Generic scalar Kalman filter.

Smooths any noisy numeric time-series (login rate, file-mod rate,
request rate, etc.). Contains zero domain-specific logic.

Tuning:
- process_variance (Q): expected natural drift of the true value between
  readings. Too low → sluggish; too high → tracks noise.
- measurement_variance (R): how much to trust each individual reading.
  Higher R → smoother output, slower reaction to real spikes.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SignalSmoother:
    process_variance: float = 1e-3
    measurement_variance: float = 1e-1

    def __post_init__(self):
        self._estimate: Optional[float] = None
        self._error_covariance: float = 1.0

    def update(self, measurement: float) -> float:
        """Feed one raw reading; return the smoothed estimate."""
        if self._estimate is None:
            self._estimate = measurement
            return self._estimate

        # predict
        predicted_estimate = self._estimate
        predicted_error_covariance = self._error_covariance + self.process_variance

        # update
        kalman_gain = predicted_error_covariance / (
            predicted_error_covariance + self.measurement_variance
        )
        self._estimate = predicted_estimate + kalman_gain * (
            measurement - predicted_estimate
        )
        self._error_covariance = (1 - kalman_gain) * predicted_error_covariance
        return self._estimate

    @property
    def current_estimate(self) -> Optional[float]:
        return self._estimate
