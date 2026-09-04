from datetime import datetime, timezone

from dtdaps.telemetry.ip_intelligence import (
    IPIntelligence,
    NullIPIntelligenceProvider,
    PrivateNetworkHeuristicProvider,
)
from dtdaps.telemetry.windows_security_log import (
    FailedLogonEvent,
    aggregate_into_windows,
)


def test_null_provider_always_unknown():
    provider = NullIPIntelligenceProvider()
    intel = provider.lookup("8.8.8.8")
    assert intel.is_proxy_or_vpn is False
    assert intel.asn_type == "unknown"


def test_private_heuristic_flags_rfc1918_as_internal():
    provider = PrivateNetworkHeuristicProvider()
    for ip in ["10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1"]:
        intel = provider.lookup(ip)
        assert intel.is_proxy_or_vpn is False
        assert intel.asn_type == "internal"


def test_private_heuristic_makes_no_claim_about_public_ip():
    provider = PrivateNetworkHeuristicProvider()
    intel = provider.lookup("8.8.8.8")
    # Honest about not knowing -- doesn't guess "residential" or similar.
    assert intel.asn_type == "unknown"
    assert intel.is_proxy_or_vpn is False


def test_private_heuristic_handles_garbage_input_gracefully():
    provider = PrivateNetworkHeuristicProvider()
    intel = provider.lookup("not-an-ip-address")
    assert intel == IPIntelligence()


def test_aggregate_into_windows_defaults_to_null_provider():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [FailedLogonEvent(1, base, "alice", "8.8.8.8", None, "3")]
    windows = aggregate_into_windows(events)
    assert windows[0]["is_proxy_or_vpn"] is False
    assert windows[0]["asn_type"] == "unknown"


def test_aggregate_into_windows_uses_supplied_provider():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [FailedLogonEvent(1, base, "alice", "10.0.0.5", None, "3")]
    windows = aggregate_into_windows(events, ip_intelligence=PrivateNetworkHeuristicProvider())
    assert windows[0]["asn_type"] == "internal"
    assert windows[0]["is_proxy_or_vpn"] is False


def test_aggregate_into_windows_no_source_ip_stays_unknown_even_with_provider():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [FailedLogonEvent(1, base, "alice", None, "WORKPC01", "2")]
    windows = aggregate_into_windows(events, ip_intelligence=PrivateNetworkHeuristicProvider())
    assert windows[0]["asn_type"] == "unknown"
