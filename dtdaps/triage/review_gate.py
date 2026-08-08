"""
Fail-secure quarantine gate.

Every submitted anomaly starts PENDING_REVIEW / blocked=True.
A human (or agent) must explicitly confirm or clear it.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import logging
import os
import tempfile
import uuid

from ..detectors.base_detector import AnomalyEvent

logger = logging.getLogger(__name__)


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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReviewItem":
        """Rehydrate a ReviewItem from to_dict() output (used when
        reloading a persisted ReviewGate queue from disk)."""
        return cls(
            event=AnomalyEvent.from_dict(data["event"]),
            status=ReviewStatus(data["status"]),
            blocked=data["blocked"],
            plain_language_reason=data["plain_language_reason"],
            recommended_action=data["recommended_action"],
            review_id=data["review_id"],
            created_at=data["created_at"],
            reviewed_at=data.get("reviewed_at"),
            reviewer_note=data.get("reviewer_note"),
        )


class ReviewGate:
    """
    Fail-secure quarantine queue.

    By default this is in-memory only, same as before. Pass a
    ``persist_path`` to make it durable: the full queue is written to a
    JSON file after every state change (submit/confirm/clear) and reloaded
    automatically the next time a ReviewGate is constructed with the same
    path. A blocked item that's still PENDING_REVIEW when the process dies
    is still PENDING_REVIEW — and still blocked — when it comes back up.

    This is a simple whole-file rewrite on every change, which is fine for
    the queue depths a review gate should realistically hold (pending
    human review doesn't scale to millions of rows). If your pending
    queue is consistently in the thousands, that's a signal your
    detectors are too noisy for this stage, not a reason to reach for a
    heavier datastore.

    Writes are atomic (write to a temp file, then os.replace) so a crash
    mid-write can't corrupt the persisted queue.
    """

    def __init__(self, persist_path: Optional[str] = None):
        self._queue: Dict[str, ReviewItem] = {}
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path is not None and self._persist_path.exists():
            self._load()

    def submit(self, event) -> ReviewItem:
        item = ReviewItem(
            event=event,
            status=ReviewStatus.PENDING_REVIEW,
            blocked=True,
            plain_language_reason=explain(event),
            recommended_action=event.context.get("agent_action", ""),
        )
        self._queue[item.review_id] = item
        self._save()
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
        self._save()
        return item

    def clear(self, review_id: str, note: str = "") -> ReviewItem:
        """Mark as false positive (unblocks)."""
        item = self._require(review_id)
        item.status = ReviewStatus.FALSE_POSITIVE
        item.blocked = False
        item.reviewed_at = datetime.now(timezone.utc).isoformat()
        item.reviewer_note = note
        self._save()
        return item

    def get(self, review_id: str) -> Optional[ReviewItem]:
        return self._queue.get(review_id)

    def _require(self, review_id: str) -> ReviewItem:
        if review_id not in self._queue:
            raise ValueError(f"No review item with id {review_id}")
        return self._queue[review_id]

    # -- persistence ---------------------------------------------------

    def _save(self) -> None:
        if self._persist_path is None:
            return
        payload = [item.to_dict() for item in self._queue.values()]
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp file in the same directory, then replace.
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._persist_path.parent), suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, self._persist_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _load(self) -> None:
        try:
            with open(self._persist_path, "r") as f:
                payload = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not load persisted review queue from %s (%s); "
                "starting with an empty queue.",
                self._persist_path,
                exc,
            )
            return
        for raw in payload:
            item = ReviewItem.from_dict(raw)
            self._queue[item.review_id] = item
