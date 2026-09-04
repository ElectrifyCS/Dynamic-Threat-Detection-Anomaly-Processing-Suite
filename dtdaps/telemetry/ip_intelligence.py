"""
Pluggable IP intelligence for WindowsSecurityLogCollector.

The collector honestly can't tell you whether a source IP is a
proxy/VPN/datacenter address — that requires an external data source
(a GeoIP/ASN database, a threat-intel feed, a paid API) this project
deliberately doesn't bundle, to stay stdlib-only and free of lock-in
to any one vendor.

What DTDAPS CAN do with zero external dependencies, using only the
stdlib `ipaddress` module, is tell a private/internal address apart
from a public one — a real, if narrow, signal: a failed-login storm
from a public address and one from an RFC1918 address inside your own
network call for different levels of concern.

`NullIPIntelligenceProvider` (the default) preserves the previous
behavior exactly: every field always "unknown" or `False`, nothing
guessed. `PrivateNetworkHeuristicProvider` adds the one signal
available offline. For real proxy/VPN/datacenter classification of
PUBLIC addresses, implement `IPIntelligenceProvider` against an actual
GeoIP/ASN database or API (MaxMind, ipinfo.io, a threat-intel feed,
etc.) and pass an instance of it to `WindowsBruteforceAdapter` or
`aggregate_into_windows()`.
"""

from dataclasses import dataclass
from typing import Protocol
import ipaddress


@dataclass(frozen=True)
class IPIntelligence:
    is_proxy_or_vpn: bool = False
    asn_type: str = "unknown"  # "datacenter" | "residential" | "internal" | "unknown"


class IPIntelligenceProvider(Protocol):
    def lookup(self, ip: str) -> IPIntelligence: ...


class NullIPIntelligenceProvider:
    """Default: always unknown. Matches the collector's original,
    honest-about-its-limits behavior of never guessing."""

    def lookup(self, ip: str) -> IPIntelligence:
        return IPIntelligence()


class PrivateNetworkHeuristicProvider:
    """
    A private-range source (RFC1918, loopback, link-local) is
    essentially never a public VPN/datacenter exit node, so this can
    confidently say `is_proxy_or_vpn=False`, `asn_type="internal"` for
    those. It makes NO claim about public addresses — asn_type stays
    "unknown" for them rather than guessing "residential" as a
    fallback, since it genuinely doesn't know.
    """

    def lookup(self, ip: str) -> IPIntelligence:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IPIntelligence()

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return IPIntelligence(is_proxy_or_vpn=False, asn_type="internal")

        return IPIntelligence()
