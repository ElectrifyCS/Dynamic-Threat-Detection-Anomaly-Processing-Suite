"""
Command-line interface for DTDAPS.

Lets a dev run the detection pipeline against a file of structured
events without writing any Python glue code:

    dtdaps run events.jsonl
    dtdaps run events.jsonl --config config.json
    dtdaps run events.jsonl --config config.json --persist-path queue.json

    dtdaps review list --persist-path queue.json
    dtdaps review confirm <review_id> --persist-path queue.json --note "..."
    dtdaps review clear <review_id> --persist-path queue.json --note "..."

`events.jsonl` is one JSON object per line, each shaped exactly like
the dicts ScriptRunnerAdapter.process_script_log() already expects.
See docs/ARCHITECTURE.md for the full type -> detector mapping.
"""

import argparse
import json
import logging
import sys
from typing import List, Optional

from .adapter import ScriptRunnerAdapter
from .config import load_config
from .triage import ReviewGate


def _read_jsonl(path: str) -> List[dict]:
    events = []
    with open(path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_num}: invalid JSON ({exc})") from exc
    return events


def _build_adapter(args: argparse.Namespace) -> ScriptRunnerAdapter:
    if args.config:
        config = load_config(args.config)
        if args.persist_path:
            config.review_gate_persist_path = args.persist_path
        return ScriptRunnerAdapter.from_config(config)

    adapter = ScriptRunnerAdapter(sensitivity=args.sensitivity, min_samples=args.min_samples)
    if args.persist_path:
        adapter.gate = ReviewGate(persist_path=args.persist_path)
    return adapter


def _print_item(item) -> None:
    print(f"[{item.status.value}] review_id={item.review_id}")
    print(f"  entity: {item.event.entity}   detector: {item.event.detector}")
    print(f"  {item.plain_language_reason}\n")


def _cmd_run(args: argparse.Namespace) -> int:
    adapter = _build_adapter(args)
    events = _read_jsonl(args.events_file)
    reviews = adapter.process_script_logs(events)

    if not reviews:
        print(f"Processed {len(events)} event(s). Nothing flagged.")
        return 0

    print(f"Processed {len(events)} event(s). {len(reviews)} flagged for review:\n")
    for item in reviews:
        _print_item(item)
    return 0


def _cmd_review_list(args: argparse.Namespace) -> int:
    gate = ReviewGate(persist_path=args.persist_path)
    pending = gate.pending()
    if not pending:
        print("No pending reviews.")
        return 0
    for item in pending:
        _print_item(item)
    return 0


def _cmd_review_confirm(args: argparse.Namespace) -> int:
    gate = ReviewGate(persist_path=args.persist_path)
    item = gate.confirm(args.review_id, note=args.note or "")
    print(f"Confirmed {item.review_id} as a threat (stays blocked).")
    return 0


def _cmd_review_clear(args: argparse.Namespace) -> int:
    gate = ReviewGate(persist_path=args.persist_path)
    item = gate.clear(args.review_id, note=args.note or "")
    print(f"Cleared {item.review_id} as a false positive (unblocked).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dtdaps",
        description="Dynamic Threat Detection & Anomaly Processing Suite CLI",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable INFO-level logging to stderr."
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable DEBUG-level logging to stderr."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run", help="Feed a JSONL file of events through the detection pipeline."
    )
    run_parser.add_argument("events_file", help="Path to a JSONL file (one event dict per line).")
    run_parser.add_argument("--config", help="Path to a .json/.yaml config file (see dtdaps.config).")
    run_parser.add_argument(
        "--sensitivity", type=float, default=2.5, help="Ignored if --config is given."
    )
    run_parser.add_argument(
        "--min-samples", type=int, default=10, dest="min_samples",
        help="Ignored if --config is given.",
    )
    run_parser.add_argument(
        "--persist-path", dest="persist_path",
        help="Persist the review queue to this JSON file (overrides the config's path, if any).",
    )
    run_parser.set_defaults(func=_cmd_run)

    review_parser = subparsers.add_parser(
        "review", help="Inspect or resolve a persisted review queue."
    )
    review_sub = review_parser.add_subparsers(dest="review_command", required=True)

    list_parser = review_sub.add_parser("list", help="List pending review items.")
    list_parser.add_argument("--persist-path", dest="persist_path", required=True)
    list_parser.set_defaults(func=_cmd_review_list)

    confirm_parser = review_sub.add_parser("confirm", help="Confirm a pending item as a real threat.")
    confirm_parser.add_argument("review_id")
    confirm_parser.add_argument("--persist-path", dest="persist_path", required=True)
    confirm_parser.add_argument("--note", default="")
    confirm_parser.set_defaults(func=_cmd_review_confirm)

    clear_parser = review_sub.add_parser("clear", help="Clear a pending item as a false positive.")
    clear_parser.add_argument("review_id")
    clear_parser.add_argument("--persist-path", dest="persist_path", required=True)
    clear_parser.add_argument("--note", default="")
    clear_parser.set_defaults(func=_cmd_review_clear)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
