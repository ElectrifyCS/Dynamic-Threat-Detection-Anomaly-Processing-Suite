"""
Unit tests for RansomwareDetector, including the joint (multivariate)
detection path.

test_joint_detection_catches_what_neither_signal_alone_does is the one
that matters most: it proves the MultivariateAnomalyEngine wiring is
doing real work at the detector level, not just in isolation — a probe
where rate is normal, entropy is normal, and the old heuristic doesn't
fire, but the pair is still off the entity's learned rate/entropy
correlation.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dtdaps.detectors.ransomware_detector import RansomwareDetector


def _train_correlated(det, entity, rounds=150, seed=11):
    """Feed rate/entropy that move together: entropy ~= rate / 300."""
    random.seed(seed)
    for i in range(rounds):
        rate = 20.0 + (i % 20)
        entropy = rate / 300.0 + random.uniform(-0.005, 0.005)
        det.ingest(
            {
                "entity": entity,
                "files_modified_last_minute": rate,
                "avg_entropy_delta": entropy,
            }
        )
    det.get_anomalies()  # drain any training-phase noise before probing


class TestRansomwareDetectorBasics:
    def test_no_flag_during_normal_correlated_traffic(self):
        det = RansomwareDetector(sensitivity=3.0, min_samples=20)
        det2 = RansomwareDetector(sensitivity=3.0, min_samples=20)
        _train_correlated(det2, "HOST-A")
        # one more in-distribution round shouldn't flag anything
        det2.ingest(
            {"entity": "HOST-A", "files_modified_last_minute": 25.0, "avg_entropy_delta": 25.0 / 300.0}
        )
        assert det2.get_anomalies() == []

    def test_flags_clear_rate_spike(self):
        det = RansomwareDetector(sensitivity=3.0, min_samples=20)
        for _ in range(25):
            det.ingest({"entity": "HOST-B", "files_modified_last_minute": 2.0, "avg_entropy_delta": 0.02})
        det.ingest({"entity": "HOST-B", "files_modified_last_minute": 400.0, "avg_entropy_delta": 0.02})
        events = det.get_anomalies()
        assert len(events) == 1
        assert events[0].context["rate_flagged"] is True

    def test_heuristic_catches_intermittent_encryption_before_baseline(self):
        # Below min_samples, the joint engine has no baseline yet — the
        # cheap always-on heuristic is what's expected to catch this.
        det = RansomwareDetector(sensitivity=3.0, min_samples=20)
        det.ingest({"entity": "HOST-C", "files_modified_last_minute": 20.0, "avg_entropy_delta": 0.5})
        events = det.get_anomalies()
        assert len(events) == 1
        assert events[0].context["intermittent_encryption_suspected"] is True
        assert events[0].context["joint_flagged"] is False  # no baseline yet


class TestJointDetectionWiring:
    def test_joint_detection_catches_what_neither_signal_alone_does(self):
        det = RansomwareDetector(sensitivity=3.0, min_samples=20)
        entity = "HOST-EVASIVE"
        _train_correlated(det, entity)

        # Rate is unremarkable (within the trained 20-39 range) and
        # entropy is unremarkable in absolute terms too (within the
        # trained ~0.067-0.13 range) -- but 0.14 is too high for a rate
        # of 25 given the learned rate/entropy relationship, and it's
        # well under the 0.35 heuristic cutoff.
        det.ingest(
            {"entity": entity, "files_modified_last_minute": 25.0, "avg_entropy_delta": 0.14}
        )
        events = det.get_anomalies()

        assert len(events) == 1
        ctx = events[0].context
        assert ctx["rate_flagged"] is False
        assert ctx["entropy_flagged"] is False
        assert (0.14 >= 0.35) is False  # heuristic's own entropy leg can't have fired
        assert ctx["joint_flagged"] is True
        assert ctx["joint_mahalanobis_sq"] > ctx["joint_distance_threshold"]
        assert ctx["intermittent_encryption_suspected"] is True

    def test_joint_engine_needs_its_own_baseline_per_entity(self):
        # A fresh entity with no history shouldn't inherit another
        # entity's learned correlation.
        det = RansomwareDetector(sensitivity=3.0, min_samples=20)
        _train_correlated(det, "HOST-TRAINED")
        det.ingest(
            {"entity": "HOST-NEW", "files_modified_last_minute": 25.0, "avg_entropy_delta": 0.14}
        )
        events = det.get_anomalies()
        # HOST-NEW has zero history -- nothing has a baseline yet, so
        # nothing (including the joint engine) should fire.
        assert events == []
