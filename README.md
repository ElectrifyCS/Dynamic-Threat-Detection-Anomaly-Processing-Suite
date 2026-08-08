# Dynamic Threat Detection & Anomaly Processing Suite (DTDAPS)

A runtime behavioral monitoring framework I built to detect anomalous process and script activity using statistical baselining.

I started this project to answer a simple question:  
**Can I actually design and implement a working threat-detection engine from first principles?**

The short answer is yes. This is the result.

It takes execution telemetry (file modifications, credential access, network egress, keyboard hooks, login attempts, etc.), builds per-entity baselines with Kalman-style smoothing + adaptive thresholds, and flags statistically significant deviations. Flagged events go into a fail-secure review queue that stays blocked until a human (or agent) decides what to do with them.

This is not a finished commercial product. It is a solid, working foundation that I continue to improve.

---

## What it does

| Catches | Does not catch |
|---------|----------------|
| Sudden spikes in file modification rate + entropy (ransomware-style) | Bad variable names or style issues |
| Credential-store access bursts and novel high-volume egress (infostealer-style) | Logic bugs or static vulnerabilities |
| Unauthorized global keyboard hooks + buffer write spikes (keylogger-style) | Inefficient algorithms |
| High failed-login rates, password spraying, datacenter-origin traffic (bruteforce-style) | Anything that only exists in source code |

It watches **what a process actually does at runtime**, not what the source code looks like. Pair it with a SAST tool if you also want static analysis.

---

## Quick Start

```bash
# From the project root
pip install -e .

# Or without installing (stdlib only)
PYTHONPATH=. python examples/basic_usage.py
PYTHONPATH=. python examples/full_pipeline.py
```

### Minimal example

```python
from dtdaps import AnomalyEngine

engine = AnomalyEngine(sensitivity=3.0, min_samples=10, decay=0.1)

for value in [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 25]:
    result = engine.process(value)
    if result.is_anomaly:
        print(f"Anomaly — z={result.z_score:.2f}, score={result.anomaly_score:.2f}")
```

### Full detector + review pipeline

```python
from dtdaps import (
    KeyloggerDetector, InfostealerDetector,
    RansomwareDetector, BruteforceDetector,
    ReviewGate,
)

gate = ReviewGate()
kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)

# Warm the baseline
for _ in range(12):
    kl.ingest({"type": "buffer_write", "entity": "proc_1", "writes_last_minute": 1})

# Trigger
kl.ingest({"type": "buffer_write", "entity": "proc_1", "writes_last_minute": 40})
kl.ingest({
    "type": "keyboard_hook_installed",
    "entity": "proc_1",
    "process_name": "svc_update.exe",
})

for anomaly in kl.get_anomalies():
    item = gate.submit(anomaly)
    print(f"[{item.status.value}] {item.plain_language_reason}")
```

---

## What’s inside

| Component | Role |
|-----------|------|
| `AnomalyEngine` | Core statistical engine (Kalman smoother + adaptive z-score). Designed so a sustained attack cannot slowly poison its own baseline. |
| `EntityStore` | Bounded LRU cache — keeps memory safe even with thousands of entities. |
| `KeyloggerDetector` | Unauthorized keyboard hooks + buffer-write rate spikes. |
| `InfostealerDetector` | Credential access bursts, novel egress destinations, anti-analysis hash checks. |
| `RansomwareDetector` | File-mod rate + entropy, including intermittent-encryption patterns. |
| `BruteforceDetector` | Failed logins weighted by account spray + proxy/VPN + datacenter ASN. |
| `ReviewGate` | Fail-secure quarantine. Everything stays blocked until explicitly cleared or confirmed. |
| `ScriptRunnerAdapter` | Turns raw script/process logs into detector events. |

All of the above is pure Python 3.9+ with **zero third-party dependencies**.

---

## Project layout

```
dtdaps/
├── engine/           # SignalSmoother, AdaptiveThreshold, AnomalyEngine
├── detectors/        # The four specialized detectors + NoveltyDetector
├── triage/           # ReviewGate
├── adapter.py
├── entity_store.py
examples/
tests/
docs/
```

---

## Why I built this

I wanted to prove to myself that I could take a real security problem, design the architecture, implement the statistical core, write the detectors, and end up with something that actually works end-to-end.

The core ideas came from two earlier experiments of mine:
- A custom script runner I used for controlled analysis work (I needed visibility into what the scripts were really doing).
- A GPS geofencing / spoofing-detection prototype that used the same baselining approach on a completely different telemetry stream.

This repository is the unified, cleaned-up version of those ideas.

It is still evolving. Thresholds, mappings, and schemas are intentionally exposed so they can be adjusted and extended.

---

## Extending it

1. Subclass `BaseDetector` and implement `ingest()` / `get_anomalies()`.
2. Use `EntityStore` + `AnomalyEngine` inside your detector.
3. Put `human_readable_summary`, `agent_action`, and `false_positive_check` in the event `context`.
4. Wire new event types into `ScriptRunnerAdapter._route()`.
5. Add baseline-then-spike tests.

See `docs/ARCHITECTURE.md` for the full contracts.

---

## License

MIT. Use it for defensive and educational purposes in environments you own or are authorized to test.
