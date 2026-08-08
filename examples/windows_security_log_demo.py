"""
Live demo: real Windows Security event log -> BruteforceDetector.

This is the one example in this repo that isn't synthetic data — it
reads your actual local Security log via `wevtutil` and runs real
failed-logon telemetry through the detector.

Requirements:
  - Windows only (uses wevtutil, which ships with the OS).
  - Run as Administrator, or from an account in the
    "Event Log Readers" group — otherwise wevtutil will be denied
    access to the Security channel.
  - Sensitivity/min_samples are set low here purely so the demo can
    show *something* without needing a real brute-force attempt in
    your log history. Use higher values (the defaults on
    BruteforceDetector) for anything resembling production use.

Usage:
    PYTHONPATH=. python examples/windows_security_log_demo.py
    PYTHONPATH=. python examples/windows_security_log_demo.py --loop 30
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dtdaps import WindowsBruteforceAdapter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loop",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Poll repeatedly every SECONDS instead of running once.",
    )
    parser.add_argument(
        "--sensitivity", type=float, default=2.5,
        help="Lower = more sensitive (default: 2.5).",
    )
    parser.add_argument(
        "--min-samples", type=int, default=10,
        help="Minutes of baseline needed before flagging (default: 10).",
    )
    args = parser.parse_args()

    adapter = WindowsBruteforceAdapter(
        sensitivity=args.sensitivity, min_samples=args.min_samples
    )

    def poll_once():
        try:
            reviews = adapter.poll()
        except RuntimeError as exc:
            print(f"[error] {exc}")
            return
        if not reviews:
            print("[poll] no new failed-logon activity.")
            return
        for item in reviews:
            print(f"[{item.status.value}] {item.plain_language_reason}")

    if args.loop:
        print(f"Polling every {args.loop}s. Ctrl+C to stop.")
        try:
            while True:
                poll_once()
                time.sleep(args.loop)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        poll_once()


if __name__ == "__main__":
    main()
