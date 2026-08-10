"""
base_detector.py

The contract between Phase 1 (detection, your side) and Phase 2
(insight + mitigation, her side). Every detector -- bruteforce,
ransomware, whatever comes later -- implements this interface and
emits AnomalyEvent objects in this exact shape. Agree on this schema
together before either of you builds much further; it's the seam
where the two halves of the project meet.

Note on "Phase 2" above: this predates docs/phase_plan.md's later,
more specific phase naming (Phase 2 = LLM Triage there). Read "Phase 2"
in this docstring loosely, as "whatever consumes AnomalyEvents
downstream" -- not a claim about which literal phase that is.
"""

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import uuid


@dataclass
class AnomalyEvent:
    detector: str              # e.g. "bruteforce_login_rate"
    malware_category: str      # e.g. "bruteforce", "ransomware", "rat", "trojan"
    entity: str                # user id, ip, hostname -- whatever this event is about
    anomaly_score: float       # 0-1, from AnomalyEngine
    z_score: float
    raw_value: float
    smoothed_value: float
    context: dict = field(default_factory=dict)   # recent history, baseline, etc.
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


# Context keys every AnomalyEvent needs to be actionable by a human
# reviewer or a downstream LLM -- not just a bare score. Centralized
# here (rather than duplicated in each detector or each caller) so
# there's exactly one place that defines "what makes an event complete."
REQUIRED_CONTEXT_KEYS = ("human_readable_summary", "agent_action", "false_positive_check")


def validate_anomaly_event(event: AnomalyEvent) -> list[str]:
    """Checks one AnomalyEvent for completeness. Returns a list of
    problems found -- empty list means valid.

    Deliberately does NOT raise or drop the event itself. What to do
    with an incomplete event (reject it, log a warning, pass it through
    flagged) is a policy decision for whoever consumes AnomalyEvents
    downstream -- the API layer, the ingestion pipeline -- not something
    to hardcode here. This function only answers "is it complete,"
    not "what happens if it isn't."
    """
    problems: list[str] = []

    if not event.detector:
        problems.append("detector is empty")
    if not event.malware_category:
        problems.append("malware_category is empty")
    if not event.entity:
        problems.append("entity is empty")

    # Guards against the exact class of bug the zero-variance fix addressed:
    # a broken score computation silently producing inf/NaN instead of a
    # real number. This check exists so that class of failure can never
    # silently leave the detection layer again, regardless of which
    # detector produces it or what future bug might reintroduce something
    # similar.
    if not isinstance(event.anomaly_score, (int, float)) or not math.isfinite(event.anomaly_score):
        problems.append(f"anomaly_score is not a finite number: {event.anomaly_score!r}")
    elif not (0.0 <= event.anomaly_score <= 1.0):
        problems.append(f"anomaly_score out of [0, 1] range: {event.anomaly_score}")

    if not isinstance(event.z_score, (int, float)) or not math.isfinite(event.z_score):
        problems.append(f"z_score is not a finite number: {event.z_score!r}")

    for key in REQUIRED_CONTEXT_KEYS:
        value = event.context.get(key)
        if not value or not isinstance(value, str) or not value.strip():
            problems.append(f"context['{key}'] is missing or empty")

    return problems


class BaseDetector(ABC):
    """Every concrete detector implements ingest() + get_anomalies().
    Keeps ingestion (how data arrives), scoring (the math, delegated
    to AnomalyEngine), and decision (score -> flag) cleanly separated
    from each other."""

    @abstractmethod
    def ingest(self, event: dict) -> None:
        """Feed in one raw event (a dict -- shape is detector-specific,
        e.g. a single log line's worth of fields)."""
        raise NotImplementedError

    @abstractmethod
    def get_anomalies(self) -> list[AnomalyEvent]:
        """Return any AnomalyEvents produced since the last call.
        Should be safe to call repeatedly (e.g. on a polling loop)."""
        raise NotImplementedError
