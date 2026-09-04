"""
Dynamic Threat Detection & Anomaly Processing Suite (DTDAPS)

Extensible runtime behavioral monitoring framework.
Detects anomalous process/script behavior using statistical baselining
(Kalman-style smoothing + adaptive z-score thresholds) and routes
flagged events through a fail-secure review gate.
"""

__version__ = "1.4.0"
__all__ = [
    "AnomalyEngine",
    "AnomalyResult",
    "RobustAnomalyEngine",
    "MultivariateAnomalyEngine",
    "MultivariateAnomalyResult",
    "EntityStore",
    "BaseDetector",
    "AnomalyEvent",
    "KeyloggerDetector",
    "InfostealerDetector",
    "RansomwareDetector",
    "BruteforceDetector",
    "NoveltyDetector",
    "DefenseTamperingDetector",
    "DistributedSprayDetector",
    "ReviewGate",
    "ReviewItem",
    "ReviewStatus",
    "ScriptRunnerAdapter",
    "WindowsSecurityLogCollector",
    "WindowsBruteforceAdapter",
    "DTDAPSConfig",
    "load_config",
]

from .engine import (
    AnomalyEngine,
    AnomalyResult,
    RobustAnomalyEngine,
    MultivariateAnomalyEngine,
    MultivariateAnomalyResult,
)
from .entity_store import EntityStore
from .detectors import (
    BaseDetector,
    AnomalyEvent,
    KeyloggerDetector,
    InfostealerDetector,
    RansomwareDetector,
    BruteforceDetector,
    NoveltyDetector,
    DefenseTamperingDetector,
    DistributedSprayDetector,
)
from .triage import ReviewGate, ReviewItem, ReviewStatus
from .adapter import ScriptRunnerAdapter
from .telemetry import WindowsSecurityLogCollector, WindowsBruteforceAdapter
from .config import DTDAPSConfig, load_config
