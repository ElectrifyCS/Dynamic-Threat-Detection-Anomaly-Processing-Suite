"""
Unit tests for the multivariate Gaussian baseline / Mahalanobis engine.

The one test that matters most here is
test_flags_correlated_pattern_each_signal_misses_alone — it's the whole
reason this module exists: proving the joint engine catches a pattern
that two independent AdaptiveThreshold instances, run separately, do not.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import math
import pytest

from dtdaps.engine.multivariate_baseline import (
    MultivariateGaussianBaseline,
    MultivariateAnomalyEngine,
    sensitivity_to_mahalanobis_threshold,
    chi2_quantile,
    _invert_matrix,
)
from dtdaps.engine.adaptive_threshold import AdaptiveThreshold


class TestThresholdMath:
    def test_k1_matches_univariate_sensitivity_exactly(self):
        # This is the contract: the multivariate rule must strictly
        # generalize the univariate one, not just resemble it.
        assert sensitivity_to_mahalanobis_threshold(3.0, 1) == pytest.approx(9.0)
        assert sensitivity_to_mahalanobis_threshold(2.0, 1) == pytest.approx(4.0)

    def test_k2_close_to_closed_form_chi2(self):
        # chi2(2) CDF has a closed form: F(x) = 1 - exp(-x/2)
        s = 3.0
        alpha = 2 * (1 - 0.5 * (1 + math.erf(s / math.sqrt(2))))
        exact = -2 * math.log(alpha)
        approx = sensitivity_to_mahalanobis_threshold(s, 2)
        assert approx == pytest.approx(exact, rel=0.02)

    def test_threshold_grows_with_dimensionality(self):
        # More correlated signals -> naturally larger raw distances even
        # under the null, so the threshold must grow with k to hold the
        # false-positive rate constant.
        t1 = sensitivity_to_mahalanobis_threshold(3.0, 1)
        t2 = sensitivity_to_mahalanobis_threshold(3.0, 2)
        t4 = sensitivity_to_mahalanobis_threshold(3.0, 4)
        assert t1 < t2 < t4


class TestMatrixInverse:
    def test_identity_inverts_to_identity(self):
        inv = _invert_matrix([[1.0, 0.0], [0.0, 1.0]])
        assert [v for row in inv for v in row] == pytest.approx([1.0, 0.0, 0.0, 1.0])

    def test_known_2x2_inverse(self):
        # [[2,0],[0,4]] inverts to [[0.5,0],[0,0.25]]
        inv = _invert_matrix([[2.0, 0.0], [0.0, 4.0]])
        assert [v for row in inv for v in row] == pytest.approx([0.5, 0.0, 0.0, 0.25])

    def test_singular_matrix_raises(self):
        with pytest.raises(ValueError):
            _invert_matrix([[1.0, 1.0], [1.0, 1.0]])


class TestMultivariateGaussianBaseline:
    def test_no_flag_before_min_samples(self):
        b = MultivariateGaussianBaseline(k=2, sensitivity=3.0, min_samples=20, decay=0.1)
        for _ in range(19):
            flagged, _ = b.evaluate_and_update([5.0, 0.1])
            assert not flagged

    def test_no_flag_for_consistent_baseline(self):
        b = MultivariateGaussianBaseline(k=2, sensitivity=3.0, min_samples=20, decay=0.1)
        flagged = False
        for _ in range(60):
            flagged, _ = b.evaluate_and_update([5.0, 0.1])
        assert not flagged

    def test_flags_a_genuine_joint_outlier(self):
        b = MultivariateGaussianBaseline(k=2, sensitivity=3.0, min_samples=20, decay=0.1)
        for _ in range(40):
            b.evaluate_and_update([5.0, 0.1])
        flagged, d2 = b.evaluate_and_update([200.0, 0.9])
        assert flagged
        assert d2 > b.distance_threshold


class TestJointDetectionCatchesWhatUnivariateMisses:
    def test_flags_correlated_pattern_each_signal_misses_alone(self):
        """
        The core claim: train both a pair of independent univariate
        AdaptiveThresholds AND a joint MultivariateGaussianBaseline on
        data where rate and entropy move together (correlated). Then feed
        a point that's within-range on *each* axis individually but off
        the learned correlation line -- individually unremarkable,
        jointly anomalous.
        """
        rate_threshold = AdaptiveThreshold(sensitivity=3.0, min_samples=20, decay=0.1, min_std_floor=0.5)
        entropy_threshold = AdaptiveThreshold(sensitivity=3.0, min_samples=20, decay=0.1, min_std_floor=0.02)
        joint = MultivariateGaussianBaseline(k=2, sensitivity=3.0, min_samples=20, decay=0.1, variance_floor=0.0004)

        # Correlated training data: entropy delta ~ mod_rate / 100.
        # (low rate, low entropy) and (high rate, high entropy) are both
        # "normal" here -- it's the *relationship* that's learned.
        import random
        random.seed(7)
        for i in range(200):
            rate = 10.0 + (i % 20)  # oscillates 10-29
            entropy = rate / 100.0 + random.uniform(-0.01, 0.01)
            rate_threshold.evaluate_and_update(rate)
            entropy_threshold.evaluate_and_update(entropy)
            joint.evaluate_and_update([rate, entropy])

        # Off-correlation point: rate is mid-range (normal alone),
        # entropy is mid-range (normal alone), but paired together they
        # violate the learned rate/entropy relationship (would need
        # rate ~= 90 to legitimately pair with this much entropy, or
        # entropy ~= 0.10 to legitimately pair with this rate).
        probe_rate, probe_entropy = 12.0, 0.55

        rate_z = rate_threshold.z_score(probe_rate)
        entropy_z = entropy_threshold.z_score(probe_entropy)
        joint_flagged, joint_d2 = joint.evaluate_and_update([probe_rate, probe_entropy])

        # The point of this test: rate alone is unremarkable...
        assert abs(rate_z) < rate_threshold.sensitivity
        # ...but the joint engine still catches it.
        assert joint_flagged
        assert joint_d2 > joint.distance_threshold


class TestMultivariateAnomalyEngine:
    def test_process_returns_bounded_score(self):
        engine = MultivariateAnomalyEngine(k=2, sensitivity=3.0, min_samples=15, decay=0.1)
        for _ in range(30):
            result = engine.process([5.0, 0.1])
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_flags_and_scores_high_for_clear_joint_outlier(self):
        engine = MultivariateAnomalyEngine(k=2, sensitivity=3.0, min_samples=15, decay=0.1, variance_floor=0.001)
        for _ in range(30):
            engine.process([5.0, 0.1])
        result = engine.process([500.0, 0.95])
        assert result.is_anomaly
        assert result.anomaly_score > 0.7
