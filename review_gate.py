"""
Fail-secure quarantine gate.

Every submitted anomaly starts PENDING_REVIEW / blocked=True.
A human (or agent) must explicitly confirm or clear it.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ReviewStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    CONFIRMED_THREAT = "confirmed_threat"
    FALSE_POSITIVE = "false_positive"


def explain(event) -> str:
    """Build a plain-language reason for the reviewer."""
    provided = event.context.get("human_readable_summary")
    if provided:
        explanation = provided
    else:
        explanation = (
            f"Blocked because {event.entity} triggered {event.detector}, "
            f"which exceeded its anomaly threshold."
        )

    check = event.context.get("false_positive_check")
    if check and check not in explanation:
        explanation = f"{explanation} {check}"
    return explanation


@dataclass
class ReviewItem:
    event: Any
    status: ReviewStatus = ReviewStatus.PENDING_REVIEW
    blocked: bool = True
    plain_language_reason: str = ""
    recommended_action: str = ""
    review_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reviewed_at: Optional[str] = None
    reviewer_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "review_id": self.review_id,
            "status": self.status.value,
            "blocked": self.blocked,
            "plain_language_reason": self.plain_language_reason,
            "recommended_action": self.recommended_action,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
            "reviewer_note": self.reviewer_note,
            "event": self.event.to_dict() if hasattr(self.event, "to_dict") else {},
        }


class ReviewGate:
    """In-memory fail-secure quarantine queue."""

    def __init__(self):
        self._queue: Dict[str, ReviewItem] = {}

    def submit(self, event) -> ReviewItem:
        item = ReviewItem(
            event=event,
            status=ReviewStatus.PENDING_REVIEW,
            blocked=True,
            plain_language_reason=explain(event),
            recommended_action=event.context.get("agent_action", ""),
        )
        self._queue[item.review_id] = item
        return item

    def pending(self) -> List[ReviewItem]:
        return [i for i in self._queue.values() if i.status == ReviewStatus.PENDING_REVIEW]

    def confirm(self, review_id: str, note: str = "") -> ReviewItem:
        """Mark as confirmed threat (stays blocked)."""
        item = self._require(review_id)
        item.status = ReviewStatus.CONFIRMED_THREAT
        item.blocked = True
        item.reviewed_at = datetime.now(timezone.utc).isoformat()
        item.reviewer_note = note
        return item

    def clear(self, review_id: str, note: str = "") -> ReviewItem:
        """Mark as false positive (unblocks)."""
        item = self._require(review_id)
        item.status = ReviewStatus.FALSE_POSITIVE
        item.blocked = False
        item.reviewed_at = datetime.now(timezone.utc).isoformat()
        item.reviewer_note = note
        return item

    def get(self, review_id: str) -> Optional[ReviewItem]:
        return self._queue.get(review_id)

    def _require(self, review_id: str) -> ReviewItem:
        if review_id not in self._queue:
            raise ValueError(f"No review item with id {review_id}")
        return self._queue[review_id]
