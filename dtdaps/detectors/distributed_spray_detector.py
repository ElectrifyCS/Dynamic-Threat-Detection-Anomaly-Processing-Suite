"""
distributed_spray_detector.py

Closes the gap flagged repeatedly in the malware feedback: "Distributed
Botnets: Spreading requests across thousands of distinct IP addresses
so that no single source triggers threshold-based rate limits" and
"Low-and-Slow Approaches: Throttling the frequency of guess attempts
per target account... to stay underneath anomaly detection radar."

BruteforceDetector is keyed PER SOURCE ENTITY (per IP/user) -- correct
for a single attacker hammering one account, but structurally unable
to catch a distributed attack BY DESIGN: a botnet spreads load across
many sources specifically so none of them individually cross a
threshold. No amount of tuning BruteforceDetector's sensitivity fixes
this -- it's the wrong axis. This detector watches a different axis:
per TARGET ACCOUNT, aggregated across every source hitting it.

Uses CUSUM (cumulative sum) rather than the z-score/EMA approach used
elsewhere, on purpose: CUSUM is specifically suited to catching a
SUSTAINED, gradual accumulation of small deviations that would each
individually look unremarkable -- exactly the "low-and-slow" evasion
pattern. A z-score check on any single minute's count would see
nothing; CUSUM accumulates evidence across many minutes and flags
once the sustained pressure crosses a threshold.

Expected raw event shape (ingest()):
    {
        "target_account": "admin@example.com",
        "source_entity": "ip_10.0.0.7",   # whichever source hit it this round
        "failed_attempts": 3,              # attempts THIS round, from THIS source
    }

Each distinct source contributes its own (small) count toward the
SAME target's cumulative score -- this is what lets many low-volume
sources add up to one high-confidence signal.
"""

from .base_detector import BaseDetector, AnomalyEvent


class _CUSUMTracker:
    """One-sided CUSUM, per target. Standard Page's-test formulation:
    S_i = max(0, S_{i-1} + (x_i - expected_mean - slack)).
    `slack` is tolerance for ordinary noise (occasional legitimate
    failed logins); only SUSTAINED pressure above that tolerance
    accumulates."""

    def __init__(self, expected_mean: float, slack: float, threshold: float):
        self.expected_mean = expected_mean
        self.slack = slack
        self.threshold = threshold
        self.current_score = 0.0

    def update(self, value: float) -> tuple[bool, float]:
        deviation = value - self.expected_mean - self.slack
        self.current_score = max(0.0, self.current_score + deviation)

        if self.current_score > self.threshold:
            alert_score = self.current_score
            self.current_score = 0.0   # reset after alert, standard CUSUM practice
            return True, alert_score

        return False, self.current_score


class DistributedSprayDetector(BaseDetector):
    def __init__(
        self,
        expected_mean: float = 1.0,
        slack: float = 0.5,
        threshold: float = 10.0,
        min_distinct_sources: int = 3,
    ):
        self.expected_mean = expected_mean
        self.slack = slack
        self.threshold = threshold
        # A single source slowly building up CUSUM pressure alone is
        # just BruteforceDetector's job (and its per-entity baseline
        # already covers that case). This detector's whole point is
        # MULTIPLE sources converging on one target -- require at
        # least a few distinct sources before treating this as
        # "distributed," not just "one patient attacker."
        self.min_distinct_sources = min_distinct_sources

        self._trackers: dict[str, _CUSUMTracker] = {}
        self._sources_seen: dict[str, set] = {}
        self._pending: list[AnomalyEvent] = []

    def _tracker_for(self, target: str) -> _CUSUMTracker:
        if target not in self._trackers:
            self._trackers[target] = _CUSUMTracker(self.expected_mean, self.slack, self.threshold)
            self._sources_seen[target] = set()
        return self._trackers[target]

    def ingest(self, event: dict) -> None:
        target = event["target_account"]
        source = event["source_entity"]
        attempts = event.get("failed_attempts", 1)

        self._sources_seen[target] = self._sources_seen.get(target, set())
        self._sources_seen[target].add(source)

        tracker = self._tracker_for(target)
        flagged, score = tracker.update(attempts)

        distinct_sources = len(self._sources_seen[target])

        if flagged and distinct_sources >= self.min_distinct_sources:
            summary = (
                f"Blocked a distributed credential attack against '{target}'. "
                f"{distinct_sources} distinct sources have made sustained login attempts "
                f"against this single account -- no individual source crossed a per-IP "
                f"threshold, but the accumulated pressure across all of them did. "
                f"Consistent with a botnet spreading requests to stay under any single "
                f"source's rate limit."
            )
            self._pending.append(
                AnomalyEvent(
                    detector="distributed_spray_cusum",
                    malware_category="bruteforce",
                    entity=target,
                    anomaly_score=min(0.5 + 0.05 * distinct_sources, 1.0),
                    z_score=0.0,   # CUSUM score, not z-score-based -- not directly comparable
                    raw_value=score,
                    smoothed_value=score,
                    context={
                        "signal": "distributed_spray_cusum",
                        "distinct_sources": distinct_sources,
                        "cusum_score_at_alert": score,
                        "target_account": target,
                        "note": "sustained low-volume-per-source pressure accumulated via CUSUM, not a single-source rate spike",
                        "human_readable_summary": summary,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": (
                            "Pending human review to rule out a widespread legitimate "
                            "MFA/SSO outage causing many real users to fail login around "
                            "the same time."
                        ),
                    },
                )
            )
            # reset source tracking for this target after an alert,
            # matching the CUSUM score reset -- otherwise the source
            # count would just keep growing forever across the whole
            # detector's lifetime instead of reflecting THIS incident
            self._sources_seen[target] = set()
        elif flagged:
            # CUSUM crossed threshold but from too few distinct
            # sources to call it "distributed" -- reset the score
            # anyway so it doesn't stay silently elevated, but don't
            # emit an event; this is BruteforceDetector's territory
            pass

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out


if __name__ == "__main__":
    detector = DistributedSprayDetector(expected_mean=1.0, slack=0.5, threshold=10.0, min_distinct_sources=3)

    # simulate a botnet: 8 different low-volume sources, each making
    # 2-3 attempts against the same target -- individually unremarkable
    sources = [f"ip_10.0.0.{i}" for i in range(1, 9)]
    for round_num in range(6):
        for src in sources:
            detector.ingest({
                "target_account": "admin@example.com",
                "source_entity": src,
                "failed_attempts": 2,
            })

    for anomaly in detector.get_anomalies():
        print(anomaly.to_dict())
