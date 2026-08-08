"""
Unit tests for the domain-agnostic statistical core.

These are deliberately isolated from the detectors — if something here
breaks, the bug is in the math, not in a detector's interpretation of it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from dtdaps.engine.signal_smoother import SignalSmoother
from dtdaps.engine.adaptive_threshold import AdaptiveThreshold
from dtdaps.engine.anomaly_engine import AnomalyEngine, z_to_score
from dtdaps.entity_store import EntityStore


# ---------------------------------------------------------------------------
# SignalSmoother
# ---------------------------------------------------------------------------

class TestSignalSmoother:
    def test_first_reading_passes_through_unchanged(self):
        s = SignalSmoother()
        assert s.update(5.0) == 5.0

    def test_current_estimate_is_none_before_first_update(self):
        s = SignalSmoother()
        assert s.current_estimate is None

    def test_smooths_toward_a_constant_signal(self):
        s = SignalSmoother(process_variance=1e-3, measurement_variance=1e-1)
        for _ in range(50):
            estimate = s.update(10.0)
        assert estimate == pytest.approx(10.0, abs=0.05)

    def test_dampens_a_single_noisy_spike(self):
        s = SignalSmoother(process_variance=1e-3, measurement_variance=1e-1)
        for _ in range(30):
            s.update(2.0)
        spiked = s.update(200.0)
        # The whole point of the smoother: one spike should move the
        # estimate, but nowhere near the raw spike value.
        assert 2.0 < spiked < 100.0

    def test_high_measurement_variance_smooths_more_aggressively(self):
        trusting = SignalSmoother(process_variance=1e-3, measurement_variance=1e-3)
        skeptical = SignalSmoother(process_variance=1e-3, measurement_variance=10.0)
        for _ in range(10):
            trusting.update(1.0)
            skeptical.update(1.0)
        trusting_after_spike = trusting.update(50.0)
        skeptical_after_spike = skeptical.update(50.0)
        assert skeptical_after_spike < trusting_after_spike


# ---------------------------------------------------------------------------
# AdaptiveThreshold
# ---------------------------------------------------------------------------

class TestAdaptiveThreshold:
    def test_no_flag_before_min_samples(self):
        t = AdaptiveThreshold(sensitivity=3.0, min_samples=10)
        for _ in range(9):
            flagged, z = t.evaluate_and_update(1.0)
            assert flagged is False
        # even a wild value shouldn't flag before the baseline is warm
        flagged, z = t.evaluate_and_update(1000.0)
        assert flagged is False

    def test_flags_a_clear_spike_after_baseline_established(self):
        t = AdaptiveThreshold(sensitivity=3.0, min_samples=10, stationary=True)
        for _ in range(15):
            t.evaluate_and_update(1.0)
        flagged, z = t.evaluate_and_update(500.0)
        assert flagged is True
        assert z > 3.0

    def test_does_not_flag_normal_variation(self):
        t = AdaptiveThreshold(sensitivity=3.0, min_samples=10, stationary=True)
        import random
        random.seed(42)
        for _ in range(200):
            flagged, z = t.evaluate_and_update(10 + random.uniform(-1, 1))
        assert flagged is False

    def test_zero_variance_baseline_still_flags_a_deviation(self):
        """A process that always reads 0 sensitive files must not become
        permanently blind just because std == 0."""
        t = AdaptiveThreshold(sensitivity=3.0, min_samples=10)
        for _ in range(15):
            t.evaluate_and_update(0.0)
        flagged, z = t.evaluate_and_update(8.0)
        assert flagged is True

    def test_variance_floor_prevents_early_overreaction(self):
        """A lucky-tight early window (small but nonzero variance) shouldn't
        make ordinary jitter look anomalous right after min_samples. Uses a
        tiny alternating wobble so std is nonzero but tiny — the case the
        floor exists for. (An exactly-zero-variance baseline is a separate,
        deliberately stricter code path — see the zero-variance test above.)
        """
        t = AdaptiveThreshold(
            sensitivity=3.0, min_samples=10, min_std_ratio=0.2, min_std_floor=0.5
        )
        for i in range(10):
            t.evaluate_and_update(10.0 + (0.01 if i % 2 == 0 else -0.01))
        # mild jitter right after baseline warms up
        flagged, z = t.evaluate_and_update(10.6)
        assert flagged is False

    def test_stationary_vs_drift_mode_track_differently(self):
        """Non-stationary (EMA) mode should adapt to a sustained level
        shift; stationary (Welford) mode should keep averaging it in
        with everything that came before, so it stays more skeptical."""
        stationary = AdaptiveThreshold(sensitivity=3.0, min_samples=10, stationary=True)
        drifting = AdaptiveThreshold(
            sensitivity=3.0, min_samples=10, stationary=False, decay=0.3
        )
        for _ in range(10):
            stationary.evaluate_and_update(1.0)
            drifting.evaluate_and_update(1.0)
        for _ in range(30):
            stationary.evaluate_and_update(5.0)
            drifting.evaluate_and_update(5.0)
        # drifting mode should have moved its mean much closer to the new
        # level than the stationary (all-time average) mode
        assert drifting.mean > stationary.mean

    def test_baseline_property_returns_mean_and_std(self):
        t = AdaptiveThreshold(min_samples=5, stationary=True)
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            t.evaluate_and_update(v)
        mean, std = t.baseline
        assert mean == pytest.approx(3.0)
        assert std > 0


# ---------------------------------------------------------------------------
# z_to_score / AnomalyEngine
# ---------------------------------------------------------------------------

class TestZToScore:
    def test_zero_z_gives_near_zero_score(self):
        assert z_to_score(0.0) == pytest.approx(0.0)

    def test_large_z_saturates_near_one(self):
        assert z_to_score(50.0) == pytest.approx(1.0, abs=1e-3)

    def test_score_is_bounded_in_zero_one(self):
        for z in [0, 1, 3, 10, -3, -50]:
            score = z_to_score(z)
            assert 0.0 <= score <= 1.0

    def test_score_increases_monotonically_with_abs_z(self):
        assert z_to_score(1.0) < z_to_score(2.0) < z_to_score(5.0)


class TestAnomalyEngine:
    def test_process_returns_result_with_expected_fields(self):
        engine = AnomalyEngine(sensitivity=3.0, min_samples=5)
        for _ in range(5):
            result = engine.process(1.0)
        assert hasattr(result, "raw_value")
        assert hasattr(result, "smoothed_value")
        assert hasattr(result, "z_score")
        assert hasattr(result, "anomaly_score")
        assert hasattr(result, "is_anomaly")

    def test_flags_sustained_spike_after_stable_baseline(self):
        engine = AnomalyEngine(sensitivity=3.0, min_samples=10, decay=0.1)
        for v in [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2]:
            result = engine.process(v)
        result = engine.process(25)
        assert result.is_anomaly is True
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_a_gradual_ramp_does_not_falsely_spike_every_step(self):
        """Guards against an overly twitchy engine on legitimate gradual
        load increases (e.g. a service slowly warming up)."""
        engine = AnomalyEngine(sensitivity=3.0, min_samples=10, decay=0.2)
        flags = []
        for v in range(1, 40):
            result = engine.process(float(v))
            flags.append(result.is_anomaly)
        # a smooth ramp shouldn't trip the detector on every single step
        assert sum(flags) < len(flags) / 2

    def test_baseline_mean_and_baseline_properties_are_exposed(self):
        engine = AnomalyEngine(min_samples=5, stationary=True)
        for v in [2.0, 2.0, 2.0, 2.0, 2.0]:
            engine.process(v)
        assert engine.baseline_mean == pytest.approx(2.0)
        mean, std = engine.baseline
        assert mean == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# EntityStore
# ---------------------------------------------------------------------------

class TestEntityStore:
    def test_rejects_non_positive_max_entities(self):
        with pytest.raises(ValueError):
            EntityStore(max_entities=0)

    def test_get_on_missing_entity_returns_none(self):
        store = EntityStore(max_entities=10)
        assert store.get("nope") is None

    def test_get_or_create_reuses_existing_object(self):
        store = EntityStore(max_entities=10)
        calls = []

        def factory():
            calls.append(1)
            return {"count": 0}

        obj1 = store.get_or_create("proc_1", factory)
        obj2 = store.get_or_create("proc_1", factory)
        assert obj1 is obj2
        assert len(calls) == 1  # factory only called once

    def test_len_and_contains(self):
        store = EntityStore(max_entities=10)
        store.get_or_create("a", lambda: 1)
        store.get_or_create("b", lambda: 2)
        assert len(store) == 2
        assert "a" in store
        assert "z" not in store

    def test_evicts_least_recently_used_when_full(self):
        store = EntityStore(max_entities=2)
        store.get_or_create("a", lambda: "A")
        store.get_or_create("b", lambda: "B")
        store.get_or_create("c", lambda: "C")  # should evict "a"
        assert "a" not in store
        assert "b" in store
        assert "c" in store
        assert store.eviction_count == 1

    def test_get_marks_entity_as_recently_used(self):
        """A flood of new entities shouldn't evict something that was
        just accessed, even if it was the oldest insert."""
        store = EntityStore(max_entities=2)
        store.get_or_create("a", lambda: "A")
        store.get_or_create("b", lambda: "B")
        store.get("a")  # touch "a" — it's now the most-recently-used
        store.get_or_create("c", lambda: "C")  # should evict "b", not "a"
        assert "a" in store
        assert "b" not in store

    def test_eviction_count_tracks_high_cardinality_flooding(self):
        store = EntityStore(max_entities=5)
        for i in range(20):
            store.get_or_create(f"entity_{i}", lambda: "x")
        assert store.eviction_count == 15
        assert len(store) == 5


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
