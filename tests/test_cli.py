import json

from dtdaps.cli import main
from dtdaps.triage import ReviewGate


def _write_jsonl(path, events):
    with open(path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def test_run_nothing_flagged(tmp_path, capsys):
    events_file = tmp_path / "events.jsonl"
    _write_jsonl(events_file, [{"entity": "host_01", "type": "some_unrecognized_event"}])

    exit_code = main(["run", str(events_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Nothing flagged" in captured.out


def test_run_flags_and_persists(tmp_path, capsys):
    events_file = tmp_path / "events.jsonl"
    persist_path = tmp_path / "queue.json"
    # Defense-tampering is instant/allowlist-based, so no baseline warmup needed.
    _write_jsonl(
        events_file,
        [{"entity": "host_01", "type": "security_service_stopped", "service_name": "WinDefend"}],
    )

    exit_code = main(["run", str(events_file), "--persist-path", str(persist_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "1 flagged for review" in captured.out
    assert persist_path.exists()


def test_run_with_config_overrides_spray_threshold(tmp_path, capsys):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"distributed_spray": {"threshold": 999.0, "min_distinct_sources": 2}})
    )
    events_file = tmp_path / "events.jsonl"
    events = [
        {
            "type": "distributed_login_attempt",
            "target_account": "admin@example.com",
            "source_entity": f"ip_{i}",
            "failed_attempts": 2,
        }
        for _ in range(6)
        for i in range(3)
    ]
    _write_jsonl(events_file, events)

    exit_code = main(["run", str(events_file), "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    # Threshold raised to 999 in config -- should never fire, unlike the default.
    assert "Nothing flagged" in captured.out


def test_run_missing_events_file_returns_error(tmp_path, capsys):
    exit_code = main(["run", str(tmp_path / "does_not_exist.jsonl")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_run_invalid_jsonl_line_returns_error(tmp_path, capsys):
    events_file = tmp_path / "events.jsonl"
    events_file.write_text("{not valid json\n")
    exit_code = main(["run", str(events_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_review_list_confirm_clear_roundtrip(tmp_path, capsys):
    events_file = tmp_path / "events.jsonl"
    persist_path = tmp_path / "queue.json"
    _write_jsonl(
        events_file,
        [{"entity": "host_01", "type": "security_service_stopped", "service_name": "WinDefend"}],
    )
    main(["run", str(events_file), "--persist-path", str(persist_path)])
    capsys.readouterr()  # discard `run` output

    exit_code = main(["review", "list", "--persist-path", str(persist_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "pending_review" in captured.out

    gate = ReviewGate(persist_path=str(persist_path))
    review_id = gate.pending()[0].review_id

    exit_code = main(
        ["review", "confirm", review_id, "--persist-path", str(persist_path), "--note", "yep, real"]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Confirmed" in captured.out

    reloaded = ReviewGate(persist_path=str(persist_path))
    assert reloaded.get(review_id).status.value == "confirmed_threat"
