"""
Script / process execution log adapter.

Normalizes raw telemetry and routes it to the appropriate detectors,
then submits any resulting anomalies to the ReviewGate.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .detectors import (
    KeyloggerDetector,
    InfostealerDetector,
    RansomwareDetector,
    BruteforceDetector,
    DefenseTamperingDetector,
    DistributedSprayDetector,
)
from .triage import ReviewGate, ReviewItem
from .config import DTDAPSConfig

logger = logging.getLogger(__name__)

_KEYLOGGER_EVENTS = {"keyboard_hook_installed", "keylogger_activity"}
_RANSOMWARE_EVENTS = {"file_modification", "ransomware_activity"}
_DEFENSE_TAMPERING_EVENTS = {
    "security_service_stopped",
    "destructive_command_detected",
    "security_process_terminated",
}


class ScriptRunnerAdapter:
    """
    Bridges dynamic execution traces into the detection suite.

    Each log entry is normalized, fed to the relevant detector, and any
    anomalies are submitted to the fail-secure ReviewGate.
    """

    def __init__(self, sensitivity: float = 2.5, min_samples: int = 10):
        self.gate = ReviewGate()
        self.infostealer = InfostealerDetector(
            sensitivity=sensitivity, min_samples=min_samples
        )
        self.keylogger = KeyloggerDetector(
            sensitivity=sensitivity, min_samples=min_samples
        )
        self.ransomware = RansomwareDetector(
            sensitivity=sensitivity, min_samples=min_samples
        )
        self.bruteforce = BruteforceDetector(
            sensitivity=sensitivity, min_samples=min_samples
        )
        # These two are allowlist/CUSUM-based rather than z-score-based,
        # so they don't take sensitivity/min_samples — see their own
        # module docstrings for their (differently-shaped) tuning knobs.
        self.defense_tampering = DefenseTamperingDetector()
        self.distributed_spray = DistributedSprayDetector()

    @classmethod
    def from_config(cls, config: DTDAPSConfig) -> "ScriptRunnerAdapter":
        """Build an adapter from a DTDAPSConfig (see dtdaps.config.load_config).

        Applies sensitivity/min_samples to the four z-score-based
        detectors, wires ReviewGate persistence if configured, and
        applies distributed_spray's CUSUM overrides. DefenseTamperingDetector
        has no tunable knobs and is unaffected by config.
        """
        adapter = cls(sensitivity=config.sensitivity, min_samples=config.min_samples)
        adapter.gate = ReviewGate(persist_path=config.review_gate_persist_path)
        adapter.distributed_spray = DistributedSprayDetector(
            expected_mean=config.distributed_spray.expected_mean,
            slack=config.distributed_spray.slack,
            threshold=config.distributed_spray.threshold,
            min_distinct_sources=config.distributed_spray.min_distinct_sources,
        )
        logger.info(
            "ScriptRunnerAdapter built from config: sensitivity=%s min_samples=%s "
            "persist_path=%s spray_threshold=%s",
            config.sensitivity,
            config.min_samples,
            config.review_gate_persist_path,
            config.distributed_spray.threshold,
        )
        return adapter

    def process_script_log(self, log_entry: Dict[str, Any]) -> List[ReviewItem]:
        entity = (
            log_entry.get("script_name")
            or log_entry.get("entity")
            or "unknown_script_runner"
        )
        event_type = log_entry.get("event_type") or log_entry.get("type")

        if event_type is None:
            logger.warning("Log entry for %s has no event_type/type; skipping.", entity)
            return []

        routed = self._route(event_type, entity, log_entry)
        if routed is None:
            logger.debug(
                "No detector mapped for event_type=%r (entity=%s); ignoring.",
                event_type,
                entity,
            )
            return []

        detector, payload = routed
        detector.ingest(payload)
        return [self.gate.submit(a) for a in detector.get_anomalies()]

    def process_script_logs(
        self, log_entries: Iterable[Dict[str, Any]]
    ) -> List[ReviewItem]:
        reviews: List[ReviewItem] = []
        for entry in log_entries:
            reviews.extend(self.process_script_log(entry))
        return reviews

    def _route(
        self, event_type: str, entity: str, log_entry: Dict[str, Any]
    ) -> Optional[Tuple[Any, Dict[str, Any]]]:
        if event_type in _KEYLOGGER_EVENTS:
            return self.keylogger, {
                "entity": entity,
                "type": "keyboard_hook_installed",
                "process_name": log_entry.get("process_name", entity),
            }

        if event_type == "buffer_write":
            return self.keylogger, {
                "entity": entity,
                "type": "buffer_write",
                "writes_last_minute": log_entry.get("writes_last_minute", 0),
            }

        if event_type == "credential_access":
            return self.infostealer, {
                "entity": entity,
                "type": "credential_access",
                "sensitive_path_reads_last_minute": log_entry.get(
                    "sensitive_path_reads_last_minute", 0
                ),
                "file_types": log_entry.get("file_types", []),
            }

        if event_type == "network_egress":
            return self.infostealer, {
                "entity": entity,
                "type": "network_egress",
                "destination": log_entry.get("destination", "unknown"),
                "bytes_sent": log_entry.get("bytes_sent", 0),
            }

        if event_type == "anti_analysis_check":
            return self.infostealer, {
                "entity": entity,
                "type": "anti_analysis_check",
                "queried_hash": log_entry.get("queried_hash", ""),
            }

        if event_type in _RANSOMWARE_EVENTS:
            return self.ransomware, {
                "entity": entity,
                "files_modified_last_minute": log_entry.get(
                    "files_modified_last_minute", 0
                ),
                "avg_entropy_delta": log_entry.get("avg_entropy_delta", 0.0),
            }

        if event_type == "login_attempt":
            return self.bruteforce, {
                "entity": entity,
                "failed_logins_last_minute": log_entry.get(
                    "failed_logins_last_minute", 0
                ),
                "unique_accounts_targeted": log_entry.get(
                    "unique_accounts_targeted", 1
                ),
                "is_proxy_or_vpn": log_entry.get("is_proxy_or_vpn", False),
                "asn_type": log_entry.get("asn_type", "unknown"),
            }

        if event_type in _DEFENSE_TAMPERING_EVENTS:
            return self.defense_tampering, {
                "entity": entity,
                "type": event_type,
                "service_name": log_entry.get("service_name", ""),
                "command": log_entry.get("command", ""),
                "process_name": log_entry.get("process_name", ""),
            }

        if event_type == "distributed_login_attempt":
            # Different shape on purpose: this detector's key axis is the
            # TARGET account across many sources, not a single entity.
            return self.distributed_spray, {
                "target_account": log_entry.get("target_account", entity),
                "source_entity": log_entry.get("source_entity", "unknown_source"),
                "failed_attempts": log_entry.get("failed_attempts", 1),
            }

        return None
