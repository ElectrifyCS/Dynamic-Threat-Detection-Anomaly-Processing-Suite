from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from ..entity_store import EntityStore


class KeyloggerDetector(BaseDetector):
    def __init__(self, sensitivity: float = 3.0, min_samples: int = 15, max_entities: int = 10_000):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        self._buffer_engines = EntityStore(max_entities=max_entities)
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

        self._hook_allowlist = {
            "autohotkey.exe",
            "narrator.exe",
            "magnify.exe",
            "osk.exe",
        }

    def _buffer_engine_for(self, entity: str) -> AnomalyEngine:
        return self._buffer_engines.get_or_create(
            entity,
            lambda: AnomalyEngine(
                sensitivity=self.sensitivity,
                min_samples=self.min_samples,
                stationary=False,
                decay=0.1,
            ),
        )

    def ingest(self, event: dict) -> None:
        entity = event["entity"]
        event_type = event.get("type")

        if event_type == "keyboard_hook_installed":
            self._ingest_hook_install(entity, event)
        elif event_type == "buffer_write":
            self._ingest_buffer_write(entity, event)

    def _ingest_hook_install(self, entity: str, event: dict) -> None:
        process_name = event.get("process_name", "").lower()
        if process_name in self._hook_allowlist:
            return

        self._history[entity] = self._history.get(entity, 0) + 1
        summary_str = (
            f"Quarantined process '{entity}' ({process_name or 'unknown process'}) for "
            f"installing a system-wide keyboard hook. This process is not on the "
            f"allowlist of known input-method, remapping, or accessibility tools."
        )
        self._pending.append(
            AnomalyEvent(
                detector="keylogger_hook_installed",
                malware_category="keylogger",
                entity=entity,
                anomaly_score=0.95,
                z_score=0.0,
                raw_value=1,
                smoothed_value=1,
                context={
                    "signal": "keyboard_hook_installed",
                    "process_name": process_name,
                    "recent_occurrences": self._history[entity],
                    "note": "unauthorized global keyboard hook, not on the accessibility/remap allowlist",
                    "human_readable_summary": summary_str,
                    "agent_action": "pause_and_prompt_human",
                    "false_positive_check": (
                        "Pending human review to confirm this isn't a newly installed, "
                        "legitimate remapping or accessibility tool not yet on the allowlist."
                    ),
                },
            )
        )

    def _ingest_buffer_write(self, entity: str, event: dict) -> None:
        rate = event["writes_last_minute"]
        engine = self._buffer_engine_for(entity)
        result = engine.process(rate)

        if result.is_anomaly:
            self._history[entity] = self._history.get(entity, 0) + 1
            summary_str = (
                f"Paused process '{entity}' for writing to a local buffer file at an "
                f"unusually high rate ({rate}/min against a baseline of "
                f"{engine._threshold.baseline[0]:.1f}/min) -- consistent with a keylogger "
                f"flushing captured input before exfiltration."
            )
            self._pending.append(
                AnomalyEvent(
                    detector="keylogger_buffer_write_rate",
                    malware_category="keylogger",
                    entity=entity,
                    anomaly_score=result.anomaly_score,
                    z_score=result.z_score,
                    raw_value=result.raw_value,
                    smoothed_value=result.smoothed_value,
                    context={
                        "signal": "buffer_write_rate",
                        "recent_occurrences": self._history[entity],
                        "baseline_rate": engine._threshold.baseline[0],
                        "note": "buffer write rate spike consistent with periodic keystroke-log flushing",
                        "human_readable_summary": summary_str,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": (
                            "Pending human review to rule out a legitimate autosave, logging, "
                            "or sync tool with a naturally high local write rate."
                        ),
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out
