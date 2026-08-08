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

## Adding a New Detector

1. Subclass `BaseDetector`.
2. Use `EntityStore` + `AnomalyEngine`.
3. Emit proper `AnomalyEvent`s.
4. Wire event types into `ScriptRunnerAdapter._route()`.
5. Add baseline-then-spike tests.
