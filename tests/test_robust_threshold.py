"""
Unit tests for RobustThreshold / RobustAnomalyEngine.

Mirrors the structure of test_engine_core.py's AdaptiveThreshold tests
so the two stay easy to compare — same behavior, different statistic.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from dtdaps.engine.robust_threshold import RobustThreshold, RobustAnomalyEngine


# ---------------------------------------------------------------------------
# RobustThreshold
# ---------------------------------------------------------------------------

class TestRobustThreshold:
    def test_no_flag_before_min_samples(self):
        t = RobustThreshold(sensitivity=3.0, min_samples=10)
        for i in range(9):
            flagged, z = t.evaluate_and_update(1.0)
            assert flagged is False
            assert z == 0.0

    def test_flags_a_clear_spike_after_baseline(self):
        t = RobustThreshold(sensitivity=3.0, min_samples=20, window_size=50)
        for _ in range(20):
            t.evaluate_and_update(2.0)
        flagged, z = t.evaluate_and_update(500.0)
        assert flagged is True
        assert z > 3.0

    def test_does_not_flag_normal_variation(self):
        t = RobustThreshold(sensitivity=3.0, min_samples=20, window_size=50)
        values = [2.0, 3.0, 2.5, 3.5, 2.0, 3.0, 2.5, 3.0, 2.0, 3.5] * 3
        flags = [t.evaluate_and_update(v)[0] for v in values]
        assert not any(flags[20:])

    def test_survives_outliers_up_to_near_50_percent(self):
        """
        The whole point of median/MAD: a baseline built from a window
        that's nearly half outliers should still center on the *real*
        normal value, not get dragged toward the outliers the way a
        mean would.
        """
        t = RobustThreshold(sensitivity=3.0, min_samples=20, window_size=40)
        # Interleave: 20 normal readings at 2.0, 19 outliers at 200.0
        # (just under half) — median should still land near 2.0.
        for i in range(39):
            value = 2.0 if i % 2 == 0 else 200.0
            t.evaluate_and_update(value)
        median, _ = t.baseline
        assert median == pytest.approx(2.0, abs=1.0)

    def test_baseline_before_two_samples_is_zero(self):
        t = RobustThreshold()
        assert t.baseline == (0.0, 0.0)

    def test_min_mad_floor_prevents_division_blowup(self):
        # A perfectly constant baseline has MAD=0. Without a floor,
        # any deviation at all would produce an infinite z-score.
        t = RobustThreshold(sensitivity=3.0, min_samples=10, min_mad_floor=0.05)
        for _ in range(10):
            t.evaluate_and_update(5.0)
        flagged, z = t.evaluate_and_update(5.1)
        assert math_is_finite(z)


def math_is_finite(x: float) -> bool:
    return x == x and x not in (float("inf"), float("-inf"))


# ---------------------------------------------------------------------------
# RobustAnomalyEngine
# ---------------------------------------------------------------------------

class TestRobustAnomalyEngine:
    def test_smooths_then_flags_like_anomaly_engine(self):
        engine = RobustAnomalyEngine(sensitivity=3.0, min_samples=15, window_size=40)
        for _ in range(20):
            result = engine.process(2.0)
        assert result.is_anomaly is False

        spiked = engine.process(300.0)
        assert spiked.anomaly_score > 0.5

    def test_baseline_property_matches_threshold(self):
        engine = RobustAnomalyEngine(min_samples=5, window_size=20)
        for v in [1.0, 2.0, 1.0, 2.0, 1.0, 2.0]:
            engine.process(v)
        median, robust_std = engine.baseline
        assert 0.5 <= median <= 2.5
        assert robust_std >= 0.0
