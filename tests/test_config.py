import json
import pytest

from dtdaps import ScriptRunnerAdapter
from dtdaps.config import DTDAPSConfig, DistributedSprayConfig, load_config


def test_defaults():
    config = DTDAPSConfig.from_dict({})
    assert config.sensitivity == 2.5
    assert config.min_samples == 10
    assert config.review_gate_persist_path is None
    assert config.distributed_spray == DistributedSprayConfig()


def test_overrides_applied():
    config = DTDAPSConfig.from_dict(
        {
            "sensitivity": 3.5,
            "min_samples": 20,
            "review_gate_persist_path": "queue.json",
            "distributed_spray": {"threshold": 25.0, "min_distinct_sources": 5},
        }
    )
    assert config.sensitivity == 3.5
    assert config.min_samples == 20
    assert config.review_gate_persist_path == "queue.json"
    assert config.distributed_spray.threshold == 25.0
    assert config.distributed_spray.min_distinct_sources == 5
    # Untouched spray fields keep their own defaults
    assert config.distributed_spray.expected_mean == 1.0


def test_unknown_top_level_key_raises():
    with pytest.raises(ValueError, match="Unknown config key"):
        DTDAPSConfig.from_dict({"sensitivty": 3.0})  # typo, on purpose


def test_unknown_spray_key_raises():
    with pytest.raises(ValueError, match="Unknown distributed_spray config key"):
        DTDAPSConfig.from_dict({"distributed_spray": {"thresold": 5.0}})  # typo


def test_invalid_value_type_raises_value_error():
    with pytest.raises(ValueError, match="Invalid config value"):
        DTDAPSConfig.from_dict({"sensitivity": "not-a-number"})


def test_load_config_json(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"sensitivity": 4.0, "min_samples": 12})
    )
    config = load_config(str(config_path))
    assert config.sensitivity == 4.0
    assert config.min_samples == 12


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "does_not_exist.json"))


def test_load_config_unsupported_extension_raises(tmp_path):
    bad = tmp_path / "config.ini"
    bad.write_text("sensitivity=3.0")
    with pytest.raises(ValueError, match="Unrecognized config file extension"):
        load_config(str(bad))


def test_adapter_from_config_applies_sensitivity_and_spray_overrides():
    config = DTDAPSConfig.from_dict(
        {
            "sensitivity": 5.0,
            "min_samples": 8,
            "distributed_spray": {"threshold": 999.0, "min_distinct_sources": 2},
        }
    )
    adapter = ScriptRunnerAdapter.from_config(config)

    assert adapter.keylogger.sensitivity == 5.0
    assert adapter.keylogger.min_samples == 8
    assert adapter.bruteforce.sensitivity == 5.0
    assert adapter.distributed_spray.threshold == 999.0
    assert adapter.distributed_spray.min_distinct_sources == 2

    # A CUSUM score that would've crossed the *default* threshold (10.0)
    # should NOT fire against this much higher configured threshold.
    reviews = []
    for _ in range(6):
        for src in ["ip_1", "ip_2", "ip_3"]:
            reviews.extend(
                adapter.process_script_log(
                    {
                        "type": "distributed_login_attempt",
                        "target_account": "admin@example.com",
                        "source_entity": src,
                        "failed_attempts": 2,
                    }
                )
            )
    assert reviews == []


def test_adapter_from_config_wires_persist_path(tmp_path):
    persist_path = tmp_path / "queue.json"
    config = DTDAPSConfig.from_dict(
        {"review_gate_persist_path": str(persist_path)}
    )
    adapter = ScriptRunnerAdapter.from_config(config)
    adapter.process_script_log(
        {
            "entity": "host_01",
            "type": "security_service_stopped",
            "service_name": "WinDefend",
        }
    )
    assert persist_path.exists()
