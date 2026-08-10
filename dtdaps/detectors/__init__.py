"""
Domain-specific detectors — each implements BaseDetector and emits
AnomalyEvent objects in the standardized schema.
"""

from .base_detector import BaseDetector, AnomalyEvent
from .bruteforce_detector import BruteforceDetector
from .ransomware_detector import RansomwareDetector
from .infostealer_detector import InfostealerDetector
from .novelty_detector import NoveltyDetector, NoveltyResult

from .keylogger_detector import KeyloggerDetector
from .defense_tampering_detector import DefenseTamperingDetector
from .distributed_spray_detector import DistributedSprayDetector
