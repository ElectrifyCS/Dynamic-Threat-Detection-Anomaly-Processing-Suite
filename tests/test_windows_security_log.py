"""
Tests for dtdaps.telemetry.windows_security_log.

These deliberately avoid calling the real WindowsSecurityLogCollector
I/O path (that needs an actual Windows host with wevtutil). Everything
here exercises the pure parsing/aggregation functions against fixture
XML shaped like real `wevtutil qe Security /f:xml` output, so the
suite runs the same on Linux, macOS, or Windows.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from dtdaps.telemetry.windows_security_log import (
    FailedLogonEvent,
    parse_wevtutil_xml,
    aggregate_into_windows,
    _filter_new,
)


def make_event_xml(
    record_id: int,
    system_time: str,
    target_user: str,
    ip_address: str = "-",
    workstation_name: str = "-",
    event_id: str = "4625",
) -> str:
    """Build one <Event> block matching real wevtutil /f:xml output."""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime='{system_time}'/>
    <EventRecordID>{record_id}</EventRecordID>
    <Correlation/>
    <Execution ProcessID='700' ThreadID='2000'/>
    <Channel>Security</Channel>
    <Computer>WORKPC01</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>S-1-0-0</Data>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='SubjectDomainName'>-</Data>
    <Data Name='SubjectLogonId'>0x0</Data>
    <Data Name='TargetUserSid'>S-1-0-0</Data>
    <Data Name='TargetUserName'>{target_user}</Data>
    <Data Name='TargetDomainName'>WORKPC01</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='FailureReason'>%%2313</Data>
    <Data Name='SubStatus'>0xc0000064</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='LogonProcessName'>NtLmSsp </Data>
    <Data Name='AuthenticationPackageName'>NTLM</Data>
    <Data Name='WorkstationName'>{workstation_name}</Data>
    <Data Name='TransmittedServices'>-</Data>
    <Data Name='LmPackageName'>-</Data>
    <Data Name='KeyLength'>0</Data>
    <Data Name='ProcessId'>0x0</Data>
    <Data Name='ProcessName'>-</Data>
    <Data Name='IpAddress'>{ip_address}</Data>
    <Data Name='IpPort'>0</Data>
  </EventData>
</Event>"""


# ---------------------------------------------------------------------------
# parse_wevtutil_xml
# ---------------------------------------------------------------------------

class TestParseWevtutilXml:
    def test_empty_input_returns_empty_list(self):
        assert parse_wevtutil_xml("") == []
        assert parse_wevtutil_xml("   ") == []

    def test_parses_a_single_event(self):
        xml = make_event_xml(
            record_id=101,
            system_time="2026-08-08T12:00:00.000000000Z",
            target_user="alice",
            ip_address="203.0.113.5",
        )
        events = parse_wevtutil_xml(xml)
        assert len(events) == 1
        e = events[0]
        assert e.record_id == 101
        assert e.target_user == "alice"
        assert e.source_ip == "203.0.113.5"
        assert e.timestamp == datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)

    def test_parses_multiple_sibling_events_with_no_shared_root(self):
        """This is the actual shape of wevtutil's output — no wrapping
        root element around multiple <Event> blocks."""
        xml = (
            make_event_xml(1, "2026-08-08T12:00:00.000000000Z", "alice", "10.0.0.1")
            + make_event_xml(2, "2026-08-08T12:00:05.000000000Z", "bob", "10.0.0.1")
        )
        events = parse_wevtutil_xml(xml)
        assert len(events) == 2
        assert {e.target_user for e in events} == {"alice", "bob"}

    def test_ignores_non_4625_events(self):
        xml = make_event_xml(
            1, "2026-08-08T12:00:00.000000000Z", "alice", "10.0.0.1", event_id="4624"
        )
        assert parse_wevtutil_xml(xml) == []

    def test_dash_ip_address_becomes_none(self):
        """Local/interactive logons report IpAddress as '-'."""
        xml = make_event_xml(
            1, "2026-08-08T12:00:00.000000000Z", "alice",
            ip_address="-", workstation_name="WORKPC01",
        )
        events = parse_wevtutil_xml(xml)
        assert events[0].source_ip is None
        assert events[0].workstation_name == "WORKPC01"

    def test_malformed_xml_returns_empty_list_not_an_exception(self):
        assert parse_wevtutil_xml("<Event><System>truncated") == []

    def test_one_malformed_event_does_not_block_the_rest(self):
        good = make_event_xml(1, "2026-08-08T12:00:00.000000000Z", "alice", "10.0.0.1")
        # A structurally-valid-but-incomplete second event (missing
        # TimeCreated) should just be skipped, not raise.
        broken = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>4625</EventID><EventRecordID>2</EventRecordID></System>"
            "</Event>"
        )
        events = parse_wevtutil_xml(good + broken)
        assert len(events) == 1
        assert events[0].target_user == "alice"


# ---------------------------------------------------------------------------
# aggregate_into_windows
# ---------------------------------------------------------------------------

class TestAggregateIntoWindows:
    def test_empty_events_returns_empty_list(self):
        assert aggregate_into_windows([]) == []

    def test_single_event_produces_one_window(self):
        events = [
            FailedLogonEvent(
                record_id=1,
                timestamp=datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc),
                target_user="alice",
                source_ip="203.0.113.5",
                workstation_name=None,
                logon_type="3",
            )
        ]
        windows = aggregate_into_windows(events, window_seconds=60)
        assert len(windows) == 1
        w = windows[0]
        assert w["entity"] == "203.0.113.5"
        assert w["failed_logins_last_minute"] == 1
        assert w["unique_accounts_targeted"] == 1
        assert w["is_proxy_or_vpn"] is False
        assert w["asn_type"] == "unknown"

    def test_groups_multiple_events_in_same_window_by_entity(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            FailedLogonEvent(1, base, "alice", "10.0.0.1", None, "3"),
            FailedLogonEvent(2, base.replace(second=10), "bob", "10.0.0.1", None, "3"),
            FailedLogonEvent(3, base.replace(second=20), "alice", "10.0.0.1", None, "3"),
        ]
        windows = aggregate_into_windows(events, window_seconds=60)
        assert len(windows) == 1
        assert windows[0]["failed_logins_last_minute"] == 3
        assert windows[0]["unique_accounts_targeted"] == 2  # alice, bob

    def test_splits_events_into_separate_time_windows(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        later = datetime(2026, 8, 8, 12, 5, 0, tzinfo=timezone.utc)
        events = [
            FailedLogonEvent(1, base, "alice", "10.0.0.1", None, "3"),
            FailedLogonEvent(2, later, "alice", "10.0.0.1", None, "3"),
        ]
        windows = aggregate_into_windows(events, window_seconds=60)
        assert len(windows) == 2
        assert all(w["failed_logins_last_minute"] == 1 for w in windows)

    def test_separates_different_source_entities(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            FailedLogonEvent(1, base, "alice", "10.0.0.1", None, "3"),
            FailedLogonEvent(2, base, "bob", "10.0.0.2", None, "3"),
        ]
        windows = aggregate_into_windows(events, window_seconds=60)
        entities = {w["entity"] for w in windows}
        assert entities == {"10.0.0.1", "10.0.0.2"}

    def test_falls_back_to_workstation_name_when_no_ip(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [FailedLogonEvent(1, base, "alice", None, "WORKPC01", "2")]
        windows = aggregate_into_windows(events)
        assert windows[0]["entity"] == "WORKPC01"

    def test_falls_back_to_unknown_source_when_neither_present(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [FailedLogonEvent(1, base, "alice", None, None, "2")]
        windows = aggregate_into_windows(events)
        assert windows[0]["entity"] == "unknown_source"


# ---------------------------------------------------------------------------
# _filter_new (incremental-poll dedup logic)
# ---------------------------------------------------------------------------

class TestFilterNew:
    def test_keeps_only_records_newer_than_last_seen(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            FailedLogonEvent(1, base, "alice", "10.0.0.1", None, "3"),
            FailedLogonEvent(2, base, "bob", "10.0.0.1", None, "3"),
            FailedLogonEvent(3, base, "carol", "10.0.0.1", None, "3"),
        ]
        new = _filter_new(events, last_record_id=1)
        assert [e.record_id for e in new] == [2, 3]

    def test_empty_when_nothing_is_newer(self):
        base = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        events = [FailedLogonEvent(1, base, "alice", "10.0.0.1", None, "3")]
        assert _filter_new(events, last_record_id=5) == []

    def test_returns_in_chronological_order_regardless_of_input_order(self):
        t1 = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 8, 12, 0, 30, tzinfo=timezone.utc)
        # deliberately out of order, as /rd:true (newest-first) would give us
        events = [
            FailedLogonEvent(2, t2, "bob", "10.0.0.1", None, "3"),
            FailedLogonEvent(1, t1, "alice", "10.0.0.1", None, "3"),
        ]
        new = _filter_new(events, last_record_id=0)
        assert [e.record_id for e in new] == [1, 2]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
