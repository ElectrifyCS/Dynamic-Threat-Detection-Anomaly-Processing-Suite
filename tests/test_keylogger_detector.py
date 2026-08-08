"""
Unit tests for KeyloggerDetector allowlist behavior.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from dtdaps.detectors.keylogger_detector import KeyloggerDetector


class TestKeyloggerAllowlist:
    """Test keyboard-hook allowlist functionality."""

    def test_allowlisted_process_does_not_trigger(self):
        """Processes in the allowlist should not generate anomalies."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_safe",
            "process_name": "narrator.exe",  # On default allowlist
        })
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 0, "Allowlisted process should not trigger"

    def test_case_insensitive_allowlist_match(self):
        """Process names should be matched case-insensitively."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_upper",
            "process_name": "NARRATOR.EXE",  # Uppercase
        })
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 0, "Case-insensitive match should allow uppercase"

    def test_unlisted_process_triggers(self):
        """Processes not on the allowlist should generate anomalies."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_malicious",
            "process_name": "mystery_tool.exe",  # Not allowlisted
        })
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 1, "Unlisted process should trigger anomaly"
        assert anomalies[0].detector == "keylogger_hook_installed"

    def test_default_allowlist_includes_accessibility_tools(self):
        """Default allowlist should include common accessibility tools."""
        kl = KeyloggerDetector()
        
        # Test a few key tools
        test_cases = [
            "nvda.exe",
            "jaws.exe",
            "zoomtext.exe",
            "ctfmon.exe",
        ]
        
        for tool in test_cases:
            kl.ingest({
                "type": "keyboard_hook_installed",
                "entity": f"proc_{tool}",
                "process_name": tool,
            })
        
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 0, "All accessibility tools should be in default allowlist"

    def test_custom_allowlist_extends_default(self):
        """Custom allowlist should extend (not replace) the default."""
        custom = {"my_custom_tool.exe"}
        kl = KeyloggerDetector(hook_allowlist=custom)
        
        # Both custom and default should be allowed
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_custom",
            "process_name": "my_custom_tool.exe",
        })
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_default",
            "process_name": "narrator.exe",
        })
        
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 0, "Both custom and default allowlist entries should be allowed"

    def test_empty_process_name_triggers(self):
        """Empty or missing process names should trigger (fail-secure)."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        kl.ingest({
            "type": "keyboard_hook_installed",
            "entity": "proc_unknown",
            "process_name": None,
        })
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 1, "Missing process name should trigger anomaly (fail-secure)"

    def test_allowlist_does_not_affect_buffer_write_detection(self):
        """Allowlist should only affect hook installation, not buffer writes."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        
        # Warm up baseline with allowlisted process
        for _ in range(15):
            kl.ingest({
                "type": "buffer_write",
                "entity": "narrator_proc",
                "writes_last_minute": 1,
            })
        
        # Spike from allowlisted process should still trigger buffer-write anomaly
        kl.ingest({
            "type": "buffer_write",
            "entity": "narrator_proc",
            "writes_last_minute": 50,
        })
        
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 1, "Allowlisted process can still trigger buffer-write anomaly"
        assert anomalies[0].detector == "keylogger_buffer_write_rate"


class TestKeyloggerBufferWrite:
    """Test buffer-write-rate anomaly detection."""

    def test_buffer_write_spike_triggers_anomaly(self):
        """Spike in buffer writes should be detected."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        
        # Establish baseline
        for _ in range(15):
            kl.ingest({
                "type": "buffer_write",
                "entity": "proc_1",
                "writes_last_minute": 2,
            })
        
        # Spike
        kl.ingest({
            "type": "buffer_write",
            "entity": "proc_1",
            "writes_last_minute": 30,
        })
        
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 1
        assert anomalies[0].malware_category == "keylogger"
        assert "baseline" in anomalies[0].context

    def test_buffer_write_per_entity(self):
        """Buffer writes should be tracked per entity."""
        kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
        
        # Entity 1: normal pattern
        for _ in range(15):
            kl.ingest({
                "type": "buffer_write",
                "entity": "proc_1",
                "writes_last_minute": 2,
            })
        
        # Entity 2: normal pattern
        for _ in range(15):
            kl.ingest({
                "type": "buffer_write",
                "entity": "proc_2",
                "writes_last_minute": 1,
            })
        
        # Only entity 1 spikes
        kl.ingest({
            "type": "buffer_write",
            "entity": "proc_1",
            "writes_last_minute": 25,
        })
        
        anomalies = kl.get_anomalies()
        assert len(anomalies) == 1
        assert anomalies[0].entity == "proc_1"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
