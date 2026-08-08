"""
Windows Security event log → BruteforceDetector.

Pulls real failed-logon records (Event ID 4625) straight from the local
Windows Security log via `wevtutil` and shapes them into the event dicts
BruteforceDetector already expects. No pywin32, no third-party packages —
`wevtutil` ships with Windows, and the output is parsed with stdlib
`xml.etree.ElementTree`.

Honest about its limits: this collector can tell you failure counts and
how many distinct accounts were targeted from a given source. It CANNOT
tell you whether a source IP is a proxy/VPN/datacenter address — that
needs an external IP-intelligence source this project doesn't include.
`is_proxy_or_vpn` and `asn_type` are always reported as unknown/False
here rather than guessed. Wire in a real IP-intel lookup before treating
those two fields as meaningful.

Requires the running process to have rights to read the Security log
(Administrator, or a member of the built-in "Event Log Readers" group).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
import subprocess
import xml.etree.ElementTree as ET

from ..detectors import BruteforceDetector
from ..triage import ReviewGate, ReviewItem

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_FAILED_LOGON_EVENT_ID = "4625"


@dataclass
class FailedLogonEvent:
    record_id: int
    timestamp: datetime
    target_user: str
    source_ip: Optional[str]      # None for local/interactive logons
    workstation_name: Optional[str]
    logon_type: Optional[str]


def _text(elem, name: str) -> Optional[str]:
    node = elem.find(name)
    return node.text if node is not None else None


def _data_field(event_data_elem, field_name: str) -> Optional[str]:
    if event_data_elem is None:
        return None
    for data in event_data_elem.findall(f"{_NS}Data"):
        if data.get("Name") == field_name:
            return data.text
    return None


def _parse_single_event(event_elem) -> Optional[FailedLogonEvent]:
    system = event_elem.find(f"{_NS}System")
    if system is None:
        return None

    event_id = _text(system, f"{_NS}EventID")
    if event_id != _FAILED_LOGON_EVENT_ID:
        return None

    record_id_text = _text(system, f"{_NS}EventRecordID")
    time_created = system.find(f"{_NS}TimeCreated")
    if record_id_text is None or time_created is None:
        return None

    system_time = time_created.get("SystemTime")
    if system_time is None:
        return None
    # wevtutil emits e.g. 2026-08-08T12:34:56.789012300Z — trim to
    # microsecond precision so %f (max 6 digits) can parse it.
    ts_trimmed = system_time[:26] + "Z" if len(system_time) > 27 else system_time
    try:
        timestamp = datetime.strptime(
            ts_trimmed, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            timestamp = datetime.strptime(
                system_time.split(".")[0] + "Z", "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    event_data = event_elem.find(f"{_NS}EventData")
    target_user = _data_field(event_data, "TargetUserName") or "unknown_user"
    source_ip = _data_field(event_data, "IpAddress")
    if source_ip in ("-", "", None):
        source_ip = None
    workstation = _data_field(event_data, "WorkstationName")
    if workstation in ("-", ""):
        workstation = None
    logon_type = _data_field(event_data, "LogonType")

    return FailedLogonEvent(
        record_id=int(record_id_text),
        timestamp=timestamp,
        target_user=target_user,
        source_ip=source_ip,
        workstation_name=workstation,
        logon_type=logon_type,
    )


def parse_wevtutil_xml(raw_xml: str) -> List[FailedLogonEvent]:
    """
    Parse the output of `wevtutil qe Security /q:"..." /f:xml`.

    wevtutil emits one or more sibling <Event> elements with no shared
    root, which isn't valid XML on its own — wrap it before parsing.
    Malformed/truncated individual <Event> blocks are skipped rather
    than failing the whole batch, since a single bad record shouldn't
    blind the collector to everything else in the log.
    """
    if not raw_xml or not raw_xml.strip():
        return []

    wrapped = f"<Events>{raw_xml}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return []

    events: List[FailedLogonEvent] = []
    for event_elem in root.findall(f"{_NS}Event"):
        try:
            parsed = _parse_single_event(event_elem)
        except (ValueError, TypeError):
            continue
        if parsed is not None:
            events.append(parsed)
    return events


def _entity_for(event: FailedLogonEvent) -> str:
    return event.source_ip or event.workstation_name or "unknown_source"


def aggregate_into_windows(
    events: List[FailedLogonEvent], window_seconds: int = 60
) -> List[Dict]:
    """
    Bucket failed-logon events into fixed time windows per source
    entity (IP, falling back to workstation name), producing dicts
    shaped exactly like BruteforceDetector.ingest() expects.

    Events are assumed pre-sorted or unsorted — this sorts internally.
    Windows with zero failures never get emitted (nothing to report),
    so a quiet source simply produces no output for that period.
    """
    if not events:
        return []

    by_entity_and_window: Dict[tuple, List[FailedLogonEvent]] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        entity = _entity_for(event)
        window_start = int(event.timestamp.timestamp()) // window_seconds
        key = (entity, window_start)
        by_entity_and_window.setdefault(key, []).append(event)

    windows = []
    for (entity, window_start), bucket in sorted(
        by_entity_and_window.items(), key=lambda kv: (kv[0][1], kv[0][0])
    ):
        unique_accounts = {e.target_user for e in bucket}
        windows.append(
            {
                "entity": entity,
                "failed_logins_last_minute": len(bucket),
                "unique_accounts_targeted": len(unique_accounts),
                # Not derivable from the local event log alone — see
                # module docstring. Left explicit rather than guessed.
                "is_proxy_or_vpn": False,
                "asn_type": "unknown",
            }
        )
    return windows


def _filter_new(
    events: List[FailedLogonEvent], last_record_id: int
) -> List[FailedLogonEvent]:
    """Pure helper: keep only records newer than the last one we
    processed, returned in chronological order."""
    new = [e for e in events if e.record_id > last_record_id]
    return sorted(new, key=lambda e: e.timestamp)


class WindowsSecurityLogCollector:
    """
    Thin I/O wrapper around `wevtutil`. Tracks the highest record ID
    seen so repeated polls don't re-report the same events.
    """

    def __init__(self, channel: str = "Security"):
        self._channel = channel
        self._last_record_id = 0

    def fetch_new_events(self, max_events: int = 500) -> List[FailedLogonEvent]:
        cmd = [
            "wevtutil", "qe", self._channel,
            "/q:*[System[(EventID=4625)]]",
            "/f:xml",
            "/rd:true",
            f"/c:{max_events}",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=True
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "wevtutil not found on PATH — this collector only runs "
                "on Windows."
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"wevtutil failed (exit {exc.returncode}): "
                f"{exc.stderr.strip()}. This usually means the current "
                "process can't read the Security log — try running as "
                "Administrator or add the account to 'Event Log Readers'."
            ) from exc

        all_events = parse_wevtutil_xml(result.stdout)
        new_events = _filter_new(all_events, self._last_record_id)
        if all_events:
            self._last_record_id = max(e.record_id for e in all_events)
        return new_events


class WindowsBruteforceAdapter:
    """
    Ties the collector, the aggregation window, BruteforceDetector, and
    ReviewGate together into a single `.poll()` call — the real-telemetry
    counterpart to ScriptRunnerAdapter's synthetic-event path.
    """

    def __init__(
        self,
        sensitivity: float = 2.5,
        min_samples: int = 10,
        window_seconds: int = 60,
        gate: Optional[ReviewGate] = None,
    ):
        self._collector = WindowsSecurityLogCollector()
        self._detector = BruteforceDetector(
            sensitivity=sensitivity, min_samples=min_samples
        )
        self.gate = gate or ReviewGate()
        self._window_seconds = window_seconds

    def poll(self) -> List[ReviewItem]:
        """Fetch new failed-logon events since the last poll, feed them
        through the detector, and return any newly submitted reviews."""
        events = self._collector.fetch_new_events()
        if not events:
            return []

        windows = aggregate_into_windows(events, window_seconds=self._window_seconds)
        for window in windows:
            self._detector.ingest(window)

        return [self.gate.submit(a) for a in self._detector.get_anomalies()]
