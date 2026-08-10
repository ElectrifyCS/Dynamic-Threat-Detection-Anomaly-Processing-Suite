"""
ransomware_detector.py

Watches file-modification rate per host alongside entropy variance.
Updated to detect Intermittent Encryption tactics.
"""

from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from ..entity_store import EntityStore


class RansomwareDetector(BaseDetector):
    def __init__(self, sensitivity: float = 3.0, min_samples: int = 20, max_entities: int = 10_000):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        # two engines per entity (rate + entropy) -- each bounded
        # independently, same reasoning as entity_store.py
        self._rate_engines = EntityStore(max_entities=max_entities)
        self._entropy_engines = EntityStore(max_entities=max_entities)
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

    # Rate signals (files/min, logins/min, etc.) and entropy-delta signals
    # (bounded 0-1, naturally small std) sit at very different scales --
    # sharing one min_std_floor default over-floors the entropy signal and
    # can mask a genuine encryption spike. Entropy gets its own, much
    # smaller floor sized for its actual range instead of inheriting the
    # rate-signal default.
    ENTROPY_MIN_STD_FLOOR = 0.02

    def _get_engine(self, store: EntityStore, entity: str, min_std_floor: float = 0.1) -> AnomalyEngine:
        return store.get_or_create(
            entity,
            lambda: AnomalyEngine(
                sensitivity=self.sensitivity,
                min_samples=self.min_samples,
                stationary=False,
                decay=0.1,
                min_std_floor=min_std_floor,
            ),
        )

    def ingest(self, event: dict) -> None:
        entity = event["entity"]
        mod_rate = event["files_modified_last_minute"]
        entropy_delta = event.get("avg_entropy_delta", 0.0)

        rate_engine = self._get_engine(self._rate_engines, entity)
        entropy_engine = self._get_engine(
            self._entropy_engines, entity, min_std_floor=self.ENTROPY_MIN_STD_FLOOR
        )

        rate_result = rate_engine.process(mod_rate)
        entropy_result = entropy_engine.process(entropy_delta)

        intermittent_encryption = (entropy_delta >= 0.35 and mod_rate >= 15)

        if rate_result.is_anomaly or entropy_result.is_anomaly or intermittent_encryption:
            self._history[entity] = self._history.get(entity, 0) + 1

            combined_score = max(rate_result.anomaly_score, entropy_result.anomaly_score)

            if intermittent_encryption:
                if combined_score < 0.75:
                    combined_score = 0.82
                summary_str = f"Paused suspected 'intermittent encryption' on '{entity}'. The host showed moderate file modifications paired with partial encryption, a known evasion tactic."
            else:
                summary_str = f"Paused '{entity}' from modifying files at an unusually high speed. The contents of the files changed drastically (high entropy), which usually indicates encryption."

            self._pending.append(
                AnomalyEvent(
                    detector="ransomware_file_behavior",
                    malware_category="ransomware",
                    entity=entity,
                    anomaly_score=combined_score,
                    z_score=max(rate_result.z_score, entropy_result.z_score),
                    raw_value=mod_rate,
                    smoothed_value=rate_result.smoothed_value,
                    context={
                        "recent_occurrences": self._history[entity],
                        "rate_flagged": rate_result.is_anomaly,
                        "entropy_flagged": entropy_result.is_anomaly,
                        "intermittent_encryption_suspected": intermittent_encryption,
                        "avg_entropy_delta": entropy_delta,
                        "baseline_mod_rate": rate_engine._threshold.baseline[0],
                        "human_readable_summary": summary_str,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": "Pending human review to verify if this is an authorized bulk file migration, compression, or backup job."
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out
