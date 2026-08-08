"""Unit tests for ReviewGate: fail-secure semantics + persistence."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from dtdaps.detectors.base_detector import AnomalyEvent
from dtdaps.triage.review_gate import ReviewGate, ReviewStatus


def make_event(entity="proc_1", **overrides):
    defaults = dict(
        detector="test_detector",
        malware_category="ransomware",
        entity=entity,
        anomaly_score=0.9,
        z_score=5.0,
        raw_value=20,
        smoothed_value=18.2,
        context={
            "human_readable_summary": f"{entity} did something unusual.",
            "agent_action": "pause_and_prompt_human",
            "false_positive_check": "Rule out a scheduled backup job.",
        },
    )
    defaults.update(overrides)
    return AnomalyEvent(**defaults)


# ---------------------------------------------------------------------------
# Core fail-secure behavior (in-memory)
# ---------------------------------------------------------------------------

class TestReviewGateCore:
    def test_submit_starts_pending_and_blocked(self):
        gate = ReviewGate()
        item = gate.submit(make_event())
        assert item.status == ReviewStatus.PENDING_REVIEW
        assert item.blocked is True

    def test_pending_lists_only_unreviewed_items(self):
        gate = ReviewGate()
        item = gate.submit(make_event())
        assert item in gate.pending()
        gate.clear(item.review_id)
        assert item not in gate.pending()

    def test_confirm_stays_blocked(self):
        gate = ReviewGate()
        item = gate.submit(make_event())
        confirmed = gate.confirm(item.review_id, note="Verified with SOC.")
        assert confirmed.status == ReviewStatus.CONFIRMED_THREAT
        assert confirmed.blocked is True
        assert confirmed.reviewer_note == "Verified with SOC."
        assert confirmed.reviewed_at is not None

    def test_clear_unblocks(self):
        gate = ReviewGate()
        item = gate.submit(make_event())
        cleared = gate.clear(item.review_id, note="Known backup job.")
        assert cleared.status == ReviewStatus.FALSE_POSITIVE
        assert cleared.blocked is False

    def test_get_unknown_review_id_returns_none(self):
        gate = ReviewGate()
        assert gate.get("does-not-exist") is None

    def test_confirm_unknown_review_id_raises(self):
        gate = ReviewGate()
        with pytest.raises(ValueError):
            gate.confirm("does-not-exist")

    def test_explain_uses_provided_summary_and_false_positive_check(self):
        gate = ReviewGate()
        item = gate.submit(make_event(entity="proc_42"))
        assert "proc_42 did something unusual." in item.plain_language_reason
        assert "Rule out a scheduled backup job." in item.plain_language_reason

    def test_explain_falls_back_when_no_summary_provided(self):
        gate = ReviewGate()
        event = make_event(context={})
        item = gate.submit(event)
        assert event.entity in item.plain_language_reason
        assert event.detector in item.plain_language_reason


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestReviewGatePersistence:
    def test_no_file_written_without_persist_path(self, tmp_path):
        gate = ReviewGate()
        gate.submit(make_event())
        assert list(tmp_path.iterdir()) == []

    def test_persist_path_writes_a_file_on_submit(self, tmp_path):
        path = tmp_path / "queue.json"
        gate = ReviewGate(persist_path=str(path))
        gate.submit(make_event())
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["status"] == "pending_review"

    def test_survives_a_simulated_restart(self, tmp_path):
        path = tmp_path / "queue.json"

        gate1 = ReviewGate(persist_path=str(path))
        item = gate1.submit(make_event(entity="proc_restart_test"))
        assert item.blocked is True

        # Simulate the process dying and a fresh ReviewGate loading
        # the same file back up.
        gate2 = ReviewGate(persist_path=str(path))
        reloaded = gate2.get(item.review_id)
        assert reloaded is not None
        assert reloaded.status == ReviewStatus.PENDING_REVIEW
        assert reloaded.blocked is True
        assert reloaded.event.entity == "proc_restart_test"
        assert reloaded.plain_language_reason == item.plain_language_reason

    def test_reviewed_items_also_survive_restart(self, tmp_path):
        path = tmp_path / "queue.json"
        gate1 = ReviewGate(persist_path=str(path))
        item = gate1.submit(make_event())
        gate1.confirm(item.review_id, note="Confirmed by analyst.")

        gate2 = ReviewGate(persist_path=str(path))
        reloaded = gate2.get(item.review_id)
        assert reloaded.status == ReviewStatus.CONFIRMED_THREAT
        assert reloaded.reviewer_note == "Confirmed by analyst."

    def test_corrupt_persist_file_falls_back_to_empty_queue(self, tmp_path, caplog):
        path = tmp_path / "queue.json"
        path.write_text("{ not valid json ]")
        gate = ReviewGate(persist_path=str(path))
        assert gate.pending() == []

    def test_missing_persist_file_starts_empty_without_error(self, tmp_path):
        path = tmp_path / "does_not_exist_yet.json"
        gate = ReviewGate(persist_path=str(path))
        assert gate.pending() == []

    def test_persisted_file_is_valid_json_after_multiple_writes(self, tmp_path):
        path = tmp_path / "queue.json"
        gate = ReviewGate(persist_path=str(path))
        for i in range(5):
            gate.submit(make_event(entity=f"proc_{i}"))
        # should not raise — proves atomic replace didn't leave a partial file
        data = json.loads(path.read_text())
        assert len(data) == 5


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
