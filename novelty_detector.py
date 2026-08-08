"""
First-seen destination / value scoring for network-egress signals.
"""

from dataclasses import dataclass, field

from ..entity_store import EntityStore


@dataclass
class NoveltyResult:
    destination: str
    is_novel: bool
    bytes_sent: int
    novelty_score: float  # 0–1, non-zero only when novel + past warm-up + above volume


@dataclass
class _EntityState:
    seen: set = field(default_factory=set)
    obs_count: int = 0


class NoveltyDetector:
    def __init__(
        self,
        volume_threshold_bytes: int = 5000,
        min_prior_observations: int = 5,
        max_entities: int = 10_000,
    ):
        self.volume_threshold_bytes = volume_threshold_bytes
        self.min_prior_observations = min_prior_observations
        self._entities = EntityStore(max_entities=max_entities)

    def evaluate_and_update(
        self, entity: str, destination: str, bytes_sent: int
    ) -> NoveltyResult:
        state = self._entities.get_or_create(entity, _EntityState)

        has_baseline = state.obs_count >= self.min_prior_observations
        is_novel = has_baseline and destination not in state.seen

        if is_novel and bytes_sent >= self.volume_threshold_bytes:
            volume_ratio = min(bytes_sent / self.volume_threshold_bytes, 3.0)
            novelty_score = min(0.5 + 0.5 * (volume_ratio / 3.0), 1.0)
        else:
            novelty_score = 0.0

        state.seen.add(destination)
        state.obs_count += 1

        return NoveltyResult(
            destination=destination,
            is_novel=is_novel,
            bytes_sent=bytes_sent,
            novelty_score=novelty_score,
        )
