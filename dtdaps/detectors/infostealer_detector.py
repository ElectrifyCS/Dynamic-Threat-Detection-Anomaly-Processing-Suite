"""
infostealer_detector.py

Detects infostealer behavior across LummaC2, Rhadamanthys, and related families
using three independent telemetry signals:

Signal 1 -- Credential-store & targeted asset access bursts.
Signal 2 -- Exfiltration destination novelty.
Signal 3 -- Anti-analysis failsafe triggers.
"""

from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from .novelty_detector import NoveltyDetector
from ..entity_store import EntityStore


class InfostealerDetector(BaseDetector):
    def __init__(
        self,
        sensitivity: float = 3.0,
        min_samples: int = 15,
        volume_threshold_bytes: int = 5000,
        min_prior_observations: int = 5,
        max_entities: int = 10_000,
    ):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        self._cred_engines = EntityStore(max_entities=max_entities)
        self._novelty = NoveltyDetector(
            volume_threshold_bytes=volume_threshold_bytes,
            min_prior_observations=min_prior_observations,
            max_entities=max_entities,
        )
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

        self._lumma_failsafe_hashes = {"0x56CF7626", "0xB09406C7"}

    def _cred_engine_for(self, entity: str) -> AnomalyEngine:
        return self._cred_engines.get_or_create(
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

        if event_type == "credential_access":
            self._ingest_credential_access(entity, event)
        elif event_type == "network_egress":
            self._ingest_network_egress(entity, event)
        elif event_type == "anti_analysis_check":
            self._ingest_anti_analysis(entity, event)

    def _ingest_credential_access(self, entity: str, event: dict) -> None:
        rate = event["sensitive_path_reads_last_minute"]
        file_types = event.get("file_types", [])

        ocr_targets_present = any(ext in file_types for ext in ["png", "jpg", "bmp", "pdf", "docx"])

        engine = self._cred_engine_for(entity)
        result = engine.process(rate)

        if result.is_anomaly:
            self._history[entity] = self._history.get(entity, 0) + 1

            note_str = "burst reads across browser/wallet credential paths"
            summary_str = f"Quarantined process '{entity}' for rapidly reading sensitive files. It accessed a sudden burst of browser credentials or crypto wallets."

            if ocr_targets_present:
                note_str += " (includes media/document files targeted for OCR seed phrase scraping)"
                summary_str = f"Quarantined process '{entity}' for rapidly reading sensitive files. It targeted credentials alongside image/document files (like {', '.join(file_types)}), a common tactic used by malware like Rhadamanthys to scrape seed phrases via OCR."

            self._pending.append(
                AnomalyEvent(
                    detector="infostealer_credential_access_rate",
                    malware_category="infostealer",
                    entity=entity,
                    anomaly_score=result.anomaly_score,
                    z_score=result.z_score,
                    raw_value=result.raw_value,
                    smoothed_value=result.smoothed_value,
                    context={
                        "signal": "credential_store_access",
                        "recent_occurrences": self._history[entity],
                        "baseline_rate": engine._threshold.baseline[0],
                        "file_types_accessed": file_types,
                        "note": note_str,
                        "human_readable_summary": summary_str,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": "Pending human review to confirm if this is an authorized admin tool or legitimate threat."
                    },
                )
            )

    def _ingest_network_egress(self, entity: str, event: dict) -> None:
        destination = event["destination"]
        bytes_sent = event.get("bytes_sent", 0)

        result = self._novelty.evaluate_and_update(entity, destination, bytes_sent)

        if result.is_novel and result.novelty_score > 0:
            self._history[entity] = self._history.get(entity, 0) + 1
            self._pending.append(
                AnomalyEvent(
                    detector="infostealer_exfil_destination_novelty",
                    malware_category="infostealer",
                    entity=entity,
                    anomaly_score=result.novelty_score,
                    z_score=0.0,
                    raw_value=bytes_sent,
                    smoothed_value=bytes_sent,
                    context={
                        "signal": "exfil_destination_novelty",
                        "recent_occurrences": self._history[entity],
                        "destination": destination,
                        "note": "first-seen destination for this entity, weighted by data volume",
                        "human_readable_summary": f"Blocked a large outward data transfer. Process '{entity}' attempted to send {bytes_sent} bytes to a completely new, previously unseen destination ({destination}).",
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": "Pending human review to confirm if this is an authorized data transfer."
                    },
                )
            )

    def _ingest_anti_analysis(self, entity: str, event: dict) -> None:
        queried_hash = event.get("queried_hash", "")
        if queried_hash in self._lumma_failsafe_hashes:
            self._history[entity] = self._history.get(entity, 0) + 1
            self._pending.append(
                AnomalyEvent(
                    detector="infostealer_lumma_failsafe_trigger",
                    malware_category="infostealer",
                    entity=entity,
                    anomaly_score=1.0,
                    z_score=0.0,
                    raw_value=1,
                    smoothed_value=1,
                    context={
                        "signal": "anti_analysis_trigger",
                        "queried_hash": queried_hash,
                        "note": "high-confidence LummaC2 anti-analysis username/hostname hash evaluation",
                        "human_readable_summary": f"Quarantined process '{entity}' for attempting to evade security analysis. The process checked specific environmental hashes ({queried_hash}) to see if it was running inside a security sandbox.",
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": "Pending human review. Note: Hash checks are highly specific and rarely trigger false positives."
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out
