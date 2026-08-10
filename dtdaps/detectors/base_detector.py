from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class AnomalyEvent:
    detector: str
    malware_category: str
    entity: str
    anomaly_score: float
    raw_value: float = 0.0
    smoothed_value: float = 0.0
    z_score: float = 0.0
    context: dict = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "malware_category": self.malware_category,
            "entity": self.entity,
            "anomaly_score": self.anomaly_score,
            "raw_value": self.raw_value,
            "smoothed_value": self.smoothed_value,
            "z_score": self.z_score,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnomalyEvent":
        return cls(
            detector=data["detector"],
            malware_category=data["malware_category"],
            entity=data["entity"],
            anomaly_score=data["anomaly_score"],
            raw_value=data.get("raw_value", 0.0),
            smoothed_value=data.get("smoothed_value", 0.0),
            z_score=data.get("z_score", 0.0),
            context=data.get("context", {}),
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


def validate_anomaly_event(event: AnomalyEvent) -> List[str]:
    problems = []
    if not event.detector:
        problems.append("missing detector")
    if not event.malware_category:
        problems.append("missing malware_category")
    if not event.entity:
        problems.append("missing entity")
    if event.anomaly_score < 0.0 or event.anomaly_score > 1.0:
        problems.append(f"invalid anomaly_score: {event.anomaly_score}")
    return problems


class BaseDetector:
    def __init__(self, sensitivity: float = 3.0, min_samples: int = 10):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        self.malware_category = "general"
        self._anomalies: List[AnomalyEvent] = []
        self._engines: Dict[str, Any] = {}

    def _engine_for(self, entity: str):
        if entity not in self._engines:
            from dtdaps.engine import DetectionEngine
            self._engines[entity] = DetectionEngine(
                sensitivity=self.sensitivity, min_samples=self.min_samples
            )
        return self._engines[entity]

    def ingest(self, event: Dict[str, Any]) -> None:
        raise NotImplementedError

    def get_anomalies(self) -> List[AnomalyEvent]:
        anomalies = list(self._anomalies)
        self._anomalies.clear()
        return anomalies
