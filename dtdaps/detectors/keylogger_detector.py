"""
keylogger_detector.py

Detects keylogger-like behavioral anomalies:
1. Keyboard hook installation (WH_KEYBOARD / WH_KEYBOARD_LL) by non-allowlisted processes.
2. Sudden spikes in local buffer write rate (keystroke buffer dumps).
"""

from typing import Any, Dict, List, Optional, Set
from .base_detector import AnomalyEvent, BaseDetector

DEFAULT_ALLOWLIST = {
    "narrator.exe",
    "nvda.exe",
    "jaws.exe",
    "zoomtext.exe",
    "ctfmon.exe",
}


class KeyloggerDetector(BaseDetector):
    def __init__(
        self,
        sensitivity: float = 3.0,
        min_samples: int = 10,
        hook_allowlist: Optional[Set[str]] = None,
    ):
        super().__init__(sensitivity=sensitivity, min_samples=min_samples)
        self.malware_category = "keylogger"
        self.hook_allowlist = set(DEFAULT_ALLOWLIST)
        if hook_allowlist:
            self.hook_allowlist.update(s.lower() for s in hook_allowlist)
        self._samples: Dict[str, List[float]] = {}

    def ingest(self, event: Dict[str, Any]) -> None:
        event_type = event.get("type")
        entity = event.get("entity", "unknown")

        if event_type == "keyboard_hook_installed":
            self._ingest_hook_install(entity, event)
        elif event_type == "buffer_write":
            writes = float(event.get("writes_last_minute", 1))
            self._ingest_buffer_write(entity, writes)

    def _ingest_hook_install(self, entity: str, event: Dict[str, Any]) -> None:
        raw_proc = event.get("process_name")
        process_name = (raw_proc or "").lower()

        if process_name and process_name in self.hook_allowlist:
            return

        ev = AnomalyEvent(
            detector="keylogger_hook_installed",
            malware_category=self.malware_category,
            entity=entity,
            anomaly_score=0.95,
            raw_value=1.0,
            context={
                "process_name": process_name,
                "agent_action": "pause_and_prompt_human",
                "false_positive_check": "Verify whether process is a legitimate accessibility or macro tool not on the allowlist.",
            },
        )
        self._anomalies.append(ev)

    def _ingest_buffer_write(self, entity: str, writes: float) -> None:
        if entity not in self._samples:
            self._samples[entity] = []

        history = self._samples[entity]

        if len(history) < self.min_samples:
            history.append(writes)
            return

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std = variance ** 0.5

        history.append(writes)

        if std == 0:
            std = 0.1

        z_score = (writes - mean) / std
        if z_score >= self.sensitivity:
            score = min(1.0, 0.5 + (z_score - self.sensitivity) * 0.1)
            ev = AnomalyEvent(
                detector="keylogger_buffer_write_rate",
                malware_category=self.malware_category,
                entity=entity,
                anomaly_score=score,
                z_score=z_score,
                raw_value=writes,
                context={
                    "baseline": mean,
                    "baseline_rate": mean,
                    "z_score": z_score,
                    "agent_action": "pause_and_prompt_human",
                    "false_positive_check": "Pending human review due to unusually high local write rate.",
                },
            )
            self._anomalies.append(ev)
