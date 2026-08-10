"""
novelty_detector.py

Evaluates set-membership and destination novelty for egress connections.
Flags connection attempts to previously unseen endpoints (IPs, domains, CDNs, or webhooks),
weighted by the volume of data exfiltrated.
"""

from dataclasses import dataclass, field

from ..entity_store import EntityStore


@dataclass
class NoveltyResult:
    destination: str
    is_novel: bool
    bytes_sent: int
    novelty_score: float   # 0-1, only non-zero when is_novel is True


@dataclass
class _EntityState:
    """Both pieces of per-entity state live in one object so a single
    EntityStore eviction drops them together -- keeping the seen-set
    and the observation count in two separate dicts risked one being
    evicted without the other, silently desyncing the cold-start gate
    from the destination history it's supposed to gate."""
    seen: set = field(default_factory=set)
    obs_count: int = 0


@dataclass
class NoveltyDetector:
    volume_threshold_bytes: int = 5000     # below this, a novel dest alone is weak signal
    min_prior_observations: int = 5        # per-entity cold-start guard -- need some history first
    max_entities: int = 10_000             # bounded, same reasoning as entity_store.py

    # Global corpus: tracks every destination seen by ANY entity across the whole
    # environment, independent of any single entity's own history. Exists specifically
    # to close the single-shot exfiltration blind spot: a process that connects exactly
    # once (obs_count=0 at that moment) can NEVER satisfy min_prior_observations above --
    # a per-entity-only cold-start gate structurally cannot flag a first-ever connection,
    # no matter how suspicious the destination is. Confirmed in practice: this is how a
    # single POST to a fresh Discord/Telegram webhook slipped past detection entirely.
    global_corpus_size: int = 50_000       # bounded, same reasoning as entity_store.py
    min_global_observations: int = 20      # environment-level cold-start guard -- see below

    def __post_init__(self):
        self._entities = EntityStore(max_entities=self.max_entities)
        # Reuses EntityStore as a bounded set (destination -> True) rather than an
        # unbounded set, for the same memory-safety reasoning as everywhere else.
        self._global_destinations = EntityStore(max_entities=self.global_corpus_size)
        # Separate from len(self._global_destinations): that counts UNIQUE
        # destinations, which conflates "how much traffic have we processed"
        # with "how diverse is this environment's traffic." An org that mostly
        # talks to a handful of Microsoft/Google endpoints could take a very
        # long time to reach min_global_observations if that's measured in
        # unique destinations -- this counts total events instead, so the
        # warm-up gate reflects how much we've actually observed, not how
        # varied it happened to be.
        self._global_obs_count = 0

    def evaluate_and_update(
        self, entity: str, destination: str, bytes_sent: int
    ) -> NoveltyResult:
        state = self._entities.get_or_create(entity, _EntityState)

        # Per-entity signal: is this new for THIS specific entity, and do we trust
        # that judgment yet (enough of this entity's own history to call it "novel"
        # rather than just "first thing we've ever seen from it")?
        has_entity_baseline = state.obs_count >= self.min_prior_observations
        is_novel_for_entity = has_entity_baseline and destination not in state.seen

        # Global signal: has ANY entity in the environment ever contacted this
        # destination before? Gated by min_global_observations rather than left
        # unguarded, because with zero environment-wide history everything looks
        # "globally novel" and the app would flood with false positives the moment
        # it starts up, before it's learned anything about what's normal here.
        has_global_baseline = self._global_obs_count >= self.min_global_observations
        is_novel_globally = has_global_baseline and destination not in self._global_destinations

        is_novel = is_novel_for_entity or is_novel_globally

        if is_novel:
            volume_ratio = min(bytes_sent / self.volume_threshold_bytes, 3.0)
            novelty_score = min(0.5 + 0.5 * (volume_ratio / 3.0), 1.0)
            # A brand-new entity's first-ever connection to a globally-unseen
            # destination is a real signal, but weaker on its own than "this
            # specific, established entity has never done this" -- a new SaaS
            # integration or a legitimately new vendor domain looks identical
            # to this at the moment it first appears. Scaling down slightly
            # when ONLY the global signal fired (not corroborated by the
            # entity's own novelty check) is a deliberate, honest tradeoff:
            # this closes a real detection gap but does increase false-positive
            # surface area on genuinely new-but-legitimate destinations. Worth
            # tuning this discount once real environment data shows how often
            # that happens in practice.
            if is_novel_globally and not is_novel_for_entity:
                novelty_score *= 0.75
        else:
            novelty_score = 0.0

        state.seen.add(destination)
        state.obs_count += 1
        self._global_destinations.get_or_create(destination, lambda: True)
        self._global_obs_count += 1

        return NoveltyResult(
            destination=destination,
            is_novel=is_novel,
            bytes_sent=bytes_sent,
            novelty_score=novelty_score,
        )


if __name__ == "__main__":
    nd = NoveltyDetector(volume_threshold_bytes=5000, min_prior_observations=5)

    known = ["api.chrome.com:443", "clients.google.com:443"]
    import random
    for _ in range(8):
        r = nd.evaluate_and_update("proc_1", random.choice(known), random.randint(200, 1000))

    # Novel destination with significant exfiltration volume
    r = nd.evaluate_and_update("proc_1", "exfil-c2.shop:443", 65000)
    print("NOVEL EXFIL DETECTED:", r)
