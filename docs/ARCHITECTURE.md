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

## Adding a New Detector

1. Subclass `BaseDetector`.
2. Use `EntityStore` + `AnomalyEngine`.
3. Emit proper `AnomalyEvent`s.
4. Wire event types into `ScriptRunnerAdapter._route()`.
5. Add baseline-then-spike tests.
