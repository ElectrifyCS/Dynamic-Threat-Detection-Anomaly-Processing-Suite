# Architecture & Module Contracts

## Data Flow

```
raw log entry (dict)
      │
      ▼
ScriptRunnerAdapter._route()        # normalizes + selects detector
      │
      ▼
<Detector>.ingest(payload)          # EntityStore → AnomalyEngine.process()
      │
      ▼
<Detector>.get_anomalies()          # drains AnomalyEvent list
      │
      ▼
ReviewGate.submit(anomaly)          # → ReviewItem (PENDING_REVIEW, blocked=True)
```

## AnomalyEngine

```python
class AnomalyEngine:
    def __init__(self, sensitivity=3.0, min_samples=30, stationary=False,
                 decay=0.05, min_std_ratio=0.2, min_std_floor=0.1): ...
    def process(self, value: float) -> AnomalyResult: ...
    @property
    def baseline_mean(self) -> float: ...
    @property
    def baseline(self) -> tuple[float, float]:  # (mean, std)
```

- Zero-variance fix: entities with a constant baseline can still be flagged.
- Variance floor prevents unstable early estimates from inflating z-scores.
- `min_std_floor` is configurable per engine (rate vs entropy signals need different floors).

## BaseDetector / AnomalyEvent

Every detector implements:

```python
def ingest(self, event: dict) -> None: ...
def get_anomalies(self) -> list[AnomalyEvent]: ...
```

`AnomalyEvent.context` **must** contain:
- `human_readable_summary`
- `agent_action`
- `false_positive_check`

## Detectors and their routed event types

`ScriptRunnerAdapter._route()` maps a `log_entry["type"]` (or `["event_type"]`)
to exactly one detector and shapes the payload it expects:

| Detector | `type` values routed to it |
|----------|------------------------------|
| `KeyloggerDetector` | `keyboard_hook_installed`, `keylogger_activity`, `buffer_write` |
| `InfostealerDetector` | `credential_access`, `network_egress`, `anti_analysis_check` |
| `RansomwareDetector` | `file_modification`, `ransomware_activity` |
| `BruteforceDetector` | `login_attempt` |
| `DefenseTamperingDetector` | `security_service_stopped`, `destructive_command_detected`, `security_process_terminated` |
| `DistributedSprayDetector` | `distributed_login_attempt` (keyed by `target_account` + `source_entity`, not the usual `entity`) |

`DefenseTamperingDetector` and `DistributedSprayDetector` don't take
`sensitivity`/`min_samples` — they're allowlist- and CUSUM-based rather
than z-score-based, so `ScriptRunnerAdapter` always constructs them
with their own defaults regardless of the `sensitivity`/`min_samples`
passed to the adapter itself. See each module's docstring for its
actual tuning knobs.

## ReviewGate persistence

`ReviewGate()` is in-memory by default (unchanged behavior). Pass
`ReviewGate(persist_path="path/to/queue.json")` to make it durable:

- Every `submit` / `confirm` / `clear` atomically rewrites the JSON file
  (temp file + `os.replace`, so a crash mid-write can't corrupt it).
- On construction, if the file exists, the full queue — including status,
  reviewer notes, and the original `AnomalyEvent` — is reloaded via
  `AnomalyEvent.from_dict` / `ReviewItem.from_dict`.
- A `PENDING_REVIEW` / `blocked=True` item stays exactly that across a
  restart, which is the point: fail-secure has to survive the process
  dying, not just the process running.
- A missing or corrupt file logs a warning and starts from an empty
  queue rather than raising — a fresh deployment shouldn't crash on
  first boot.

This is a whole-file rewrite per change, which is intentionally simple.
It's fine for realistic pending-review depths; if your queue is
consistently in the thousands, that's a sign the detectors upstream are
too noisy for this stage, not a reason to swap in a database.

## Telemetry adapters (real data, not synthetic)

`dtdaps.telemetry` is where live data actually gets collected, as
opposed to `ScriptRunnerAdapter`, which shapes already-structured event
dicts regardless of where they came from.

Each collector splits into two layers:
1. Pure parse/aggregate functions — no I/O, unit-testable on any OS
   against fixture data (see `tests/test_windows_security_log.py`).
2. A thin collector class that does the actual I/O and is only
   meaningfully exercised on its target platform.

`WindowsSecurityLogCollector` pulls Event ID 4625 (failed logon)
records from the local Security log via `wevtutil` (stdlib subprocess +
`xml.etree.ElementTree` — no pywin32, no third-party deps). Requires
rights to read the Security channel (Administrator, or a member of
"Event Log Readers").

`WindowsBruteforceAdapter` wires that collector into `BruteforceDetector`
+ `ReviewGate` behind a single `.poll()` call, tracking the last-seen
`EventRecordID` so repeated polls don't double-count.

**Known gap:** `is_proxy_or_vpn` and `asn_type` can't be derived from
the local event log alone — they're always reported as `False` /
`"unknown"` here rather than guessed. A real deployment needs to wire
in an actual IP-intelligence source (GeoIP/ASN lookup, threat-intel
feed) before those two fields carry real signal.

## Adding a New Detector

1. Subclass `BaseDetector`.
2. Use `EntityStore` + `AnomalyEngine`.
3. Emit proper `AnomalyEvent`s.
4. Wire event types into `ScriptRunnerAdapter._route()`.
5. Add baseline-then-spike tests.
