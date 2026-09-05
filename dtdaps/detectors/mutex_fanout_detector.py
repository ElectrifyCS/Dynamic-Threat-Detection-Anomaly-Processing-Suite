"""
mutex_fanout_detector.py

Grounded in the diskdiag.exe RAT behavior report: the SAME mutex
("DSYS") was found held by TWO different process identities on the
same host -- exe.exe (PID 5640) and diskdiag.exe (PID 1384), the
latter launched via Task Scheduler from a different path
("Starts itself from another location" / "Starts a Microsoft
application from unusual location"). That's a malware family copying
itself to a new name and location and re-launching under a fresh
identity -- a classic evasion move to survive a cleanup that only
targeted the original name, or to blend in as a decoy-named process
("diskdiag" reads as a legitimate disk-diagnostic utility).

A hardcoded mutex name is how many malware families prevent two
copies of themselves from running at once -- it's meant to be a
private, internal implementation detail, not something that should
ever be shared across genuinely different, unrelated programs. So the
signal here isn't the mutex name itself (that changes per family and
this detector doesn't need a signature list of known-bad names to
work) -- it's the SHAPE of the pattern: one mutex, held by more than
one distinct process identity, on the same host. That's the same
fanout-counting idea as DistributedSprayDetector (many identities
converging on one thing), applied to mutex ownership instead of
login targets: legitimate software's mutex is only ever claimed by
that one program, so a second distinct identity claiming it is a
near-deterministic masquerading signal, not something that needs
statistical baselining to see.

Expected raw event shape (ingest()):
    {
        "entity": "host_01",
        "mutex_name": "DSYS",
        "process_name": "diskdiag.exe",
        "process_path": "C:\\Windows\\Temp\\diskdiag.exe",
    }
"""

from .base_detector import BaseDetector, AnomalyEvent


class MutexFanoutDetector(BaseDetector):
    def __init__(self, min_distinct_identities: int = 2):
        # How many distinct (process_name, process_path) identities
        # must claim the SAME mutex on the SAME host before this is
        # treated as masquerading rather than coincidence. Default of
        # 2 matches the grounding report exactly (exe.exe + diskdiag.exe
        # both held DSYS) -- deliberately low, since legitimate software
        # essentially never shares a mutex with an unrelated program.
        self.min_distinct_identities = min_distinct_identities

        # (entity, mutex_name) -> set of (process_name, process_path)
        self._identities_seen: dict[tuple, set] = {}
        # (entity, mutex_name) -> already flagged, so a busy mutex
        # doesn't re-alert on every subsequent event once the pattern
        # is established
        self._flagged: set = set()
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

    def ingest(self, event: dict) -> None:
        entity = event["entity"]
        mutex_name = event.get("mutex_name", "")
        if not mutex_name:
            return

        process_name = event.get("process_name", "").lower()
        process_path = event.get("process_path", "").lower()
        identity = (process_name, process_path)

        key = (entity, mutex_name)
        seen = self._identities_seen.setdefault(key, set())
        seen.add(identity)

        distinct_count = len(seen)
        if distinct_count < self.min_distinct_identities:
            return
        if key in self._flagged:
            return  # already alerted for this (entity, mutex) pair

        self._flagged.add(key)
        self._history[entity] = self._history.get(entity, 0) + 1

        identity_list = ", ".join(
            f"'{name or 'unknown'}'" + (f" ({path})" if path else "")
            for name, path in sorted(seen)
        )
        summary = (
            f"Blocked '{entity}': the mutex '{mutex_name}' is held by "
            f"{distinct_count} distinct process identities -- {identity_list}. "
            f"A mutex is normally a private implementation detail one program "
            f"uses to stop a second copy of ITSELF from running; genuinely "
            f"unrelated programs essentially never share one. This pattern is "
            f"consistent with malware copying itself to a new name/location and "
            f"re-launching under a fresh identity, e.g. to survive a cleanup "
            f"that only targeted the original name, or to blend in under a "
            f"decoy name."
        )

        self._pending.append(
            AnomalyEvent(
                detector="mutex_fanout_masquerading",
                malware_category="defense_evasion",
                entity=entity,
                anomaly_score=min(0.7 + 0.1 * distinct_count, 1.0),
                z_score=0.0,  # deterministic fanout count, not baseline-relative
                raw_value=distinct_count,
                smoothed_value=distinct_count,
                context={
                    "recent_occurrences": self._history[entity],
                    "signal": "mutex_claimed_by_multiple_identities",
                    "mutex_name": mutex_name,
                    "distinct_identity_count": distinct_count,
                    "identities": sorted(seen),
                    "human_readable_summary": summary,
                    "agent_action": "pause_and_prompt_human",
                    "false_positive_check": (
                        "Pending human review to rule out a legitimate software "
                        "update in progress (an installer briefly running "
                        "alongside the old binary under a temporary name before "
                        "the old one exits) or a monitoring tool intentionally "
                        "instrumenting another process."
                    ),
                },
            )
        )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out


if __name__ == "__main__":
    detector = MutexFanoutDetector()

    # the diskdiag.exe report pattern: same mutex, two identities
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Users\admin\AppData\Local\Temp\exe.exe",
    })
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })

    for anomaly in detector.get_anomalies():
        print(anomaly.to_dict())
