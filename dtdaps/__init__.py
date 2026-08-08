"""
Dynamic Threat Detection & Anomaly Processing Suite (DTDAPS)

Extensible runtime behavioral monitoring framework.
Detects anomalous process/script behavior using statistical baselining
(Kalman-style smoothing + adaptive z-score thresholds) and routes
flagged events through a fail-secure review gate.
"""

__version__ = "1.2.0"
__all__ = [
    "AnomalyEngine",
    "AnomalyResult",
    "EntityStore",
    "BaseDetector",
    "AnomalyEvent",
    "KeyloggerDetector",
    "InfostealerDetector",
    "RansomwareDetector",
    "BruteforceDetector",
    "NoveltyDetector",
    "ReviewGate",
    "ReviewItem",
    "ReviewStatus",
    "ScriptRunnerAdapter",
]

from .engine import AnomalyEngine, AnomalyResult
from .entity_store import EntityStore
from .detectors import (
    BaseDetector,
    AnomalyEvent,
    KeyloggerDetector,
    InfostealerDetector,
    RansomwareDetector,
    BruteforceDetector,
    NoveltyDetector,
)
from .triage import ReviewGate, ReviewItem, ReviewStatus
from .adapter import ScriptRunnerAdapter
