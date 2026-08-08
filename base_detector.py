"""
Shared contract every detector implements.

AnomalyEvent is the seam between detection and the review/triage layer.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid


@dataclass
class AnomalyEvent:
    detector: str
    malware_category: str
    entity: str
    anomaly_score: float
    z_score: float
    raw_value: Any
    smoothed_value: Any
    context: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseDetector(ABC):
    """Minimal interface: ingest one event, later drain anomalies."""

    @abstractmethod
    def ingest(self, event: Dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_anomalies(self) -> List[AnomalyEvent]:
        """Return and clear anomalies generated since last call."""
        raise NotImplementedError
