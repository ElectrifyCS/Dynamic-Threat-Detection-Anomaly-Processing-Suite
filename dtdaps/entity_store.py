"""
Bounded LRU cache mapping entity name → per-entity state object.

Every detector tracks state per entity (process, host, IP, …).
A flood of unique or spoofed names must not grow memory without bound.
This is the single place that constraint is enforced.
"""

from collections import OrderedDict
from typing import Callable, Generic, Optional, TypeVar
import logging

T = TypeVar("T")

logger = logging.getLogger(__name__)

# Every Nth eviction gets a WARNING instead of a DEBUG, so a sustained
# high-cardinality flood (e.g. a spray attack rotating source entities)
# is visible without turning on debug logging, but a normal, occasional
# eviction doesn't spam the logs.
_WARN_EVERY = 1000


class EntityStore(Generic[T]):
    """
    Bounded least-recently-used cache.

    Every get / get_or_create marks the entity most-recently-used.
    When max_entities is exceeded the least-recently-used entry is
    evicted so memory stays bounded under high-cardinality traffic.
    """

    def __init__(self, max_entities: int = 10_000):
        if max_entities <= 0:
            raise ValueError("max_entities must be positive")
        self._max_entities = max_entities
        self._store: "OrderedDict[str, T]" = OrderedDict()
        self.eviction_count = 0  # rising fast → max_entities is too low for real load

    def get(self, entity: str) -> Optional[T]:
        """Return cached object without creating, or None."""
        obj = self._store.get(entity)
        if obj is not None:
            self._store.move_to_end(entity)
        return obj

    def get_or_create(self, entity: str, factory: Callable[[], T]) -> T:
        """
        Return cached object, creating via factory() on first sight.
        Evicts least-recently-used if creation would exceed max_entities.
        """
        if entity in self._store:
            self._store.move_to_end(entity)
            return self._store[entity]

        obj = factory()
        self._store[entity] = obj
        if len(self._store) > self._max_entities:
            evicted, _ = self._store.popitem(last=False)
            self.eviction_count += 1
            if self.eviction_count % _WARN_EVERY == 0:
                logger.warning(
                    "EntityStore has evicted %d entities so far (max_entities=%d); "
                    "most recently evicted %r. Rising fast usually means "
                    "max_entities is too low for real traffic.",
                    self.eviction_count,
                    self._max_entities,
                    evicted,
                )
            else:
                logger.debug("Evicted entity %r (total evictions: %d)", evicted, self.eviction_count)
        return obj

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, entity: str) -> bool:
        return entity in self._store
