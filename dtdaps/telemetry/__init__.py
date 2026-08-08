"""
Real-world telemetry collectors.

Everything in `dtdaps.adapter` (ScriptRunnerAdapter) consumes
already-structured event dicts — it doesn't care where they came from.
This package is where those dicts actually get produced: pulling live
data from a real OS/security data source and shaping it to match what
a detector expects.

Each collector is split into two layers:
  1. A pure parsing/aggregation function — no I/O, fully unit-testable
     on any platform, against fixture data.
  2. A thin collector class that does the actual I/O (subprocess calls,
     file reads, etc.) and is only exercised on the real platform it
     targets.
"""

from .windows_security_log import (
    FailedLogonEvent,
    parse_wevtutil_xml,
    aggregate_into_windows,
    WindowsSecurityLogCollector,
    WindowsBruteforceAdapter,
)

__all__ = [
    "FailedLogonEvent",
    "parse_wevtutil_xml",
    "aggregate_into_windows",
    "WindowsSecurityLogCollector",
    "WindowsBruteforceAdapter",
]
