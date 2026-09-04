# Dynamic Threat Detection & Anomaly Processing Suite (DTDAPS)

[![Tests](https://github.com/ElectrifyCS/Dynamic-Threat-Detection-Anomaly-Processing-Suite/actions/workflows/tests.yml/badge.svg)](https://github.com/ElectrifyCS/Dynamic-Threat-Detection-Anomaly-Processing-Suite/actions/workflows/tests.yml)

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
| Security services stopped, destructive recovery commands, AV/EDR processes killed (defense-tampering) | |
| Distributed credential-stuffing spread across many sources against one account (low-and-slow spray) | |

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

### CLI

Once installed (`pip install -e .`), run the pipeline against a file of
events without writing any Python:

```bash
# events.jsonl: one JSON object per line, shaped like ScriptRunnerAdapter expects
dtdaps run events.jsonl --persist-path queue.json

# or with a config file instead of --sensitivity/--min-samples flags
dtdaps run events.jsonl --config config.json --persist-path queue.json

# inspect / resolve a persisted queue
dtdaps review list --persist-path queue.json
dtdaps review confirm <review_id> --persist-path queue.json --note "confirmed with SOC"
dtdaps review clear <review_id> --persist-path queue.json --note "planned maintenance"
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

### Running tests

```bash
pip install -e ".[dev]"
python -m pytest tests -v
```

125 tests: unit coverage for the statistical core (`SignalSmoother`, `AdaptiveThreshold`, `AnomalyEngine`, `EntityStore`), the robust (`RobustThreshold`) and multivariate (`MultivariateGaussianBaseline`) baselines, the fail-secure `ReviewGate` contract and its disk persistence, `RansomwareDetector`'s joint-detection wiring, `ScriptRunnerAdapter`'s event-type routing (including `DefenseTamperingDetector` and `DistributedSprayDetector`), the config loader, the CLI, the pluggable IP intelligence providers, plus the original end-to-end smoke test across all four core detectors.

---

## What’s inside

| Component | Role |
|-----------|------|
| `AnomalyEngine` | Core statistical engine (Kalman smoother + adaptive z-score). Designed so a sustained attack cannot slowly poison its own baseline. |
| `EntityStore` | Bounded LRU cache — keeps memory safe even with thousands of entities. |
| `KeyloggerDetector` | Unauthorized keyboard hooks + buffer-write rate spikes. |
| `InfostealerDetector` | Credential access bursts, novel egress destinations, anti-analysis hash checks. |
| `RansomwareDetector` | File-mod rate + entropy, including intermittent-encryption patterns — now also uses `MultivariateAnomalyEngine` to catch cases where rate and entropy are each individually normal but jointly off the entity's learned correlation. |
| `RobustThreshold` / `RobustAnomalyEngine` | Median/MAD-based variant of the core engine — stays accurate even when up to ~50% of the baseline window is contaminated by outliers, unlike mean/std. |
| `MultivariateGaussianBaseline` / `MultivariateAnomalyEngine` | Joint Mahalanobis-distance baseline across correlated signals, so a coordinated pattern across multiple signals gets flagged even when no single signal crosses its own threshold. |
| `BruteforceDetector` | Failed logins weighted by account spray + proxy/VPN + datacenter ASN. |
| `DefenseTamperingDetector` | Cross-cutting, allowlist-based: critical security services stopped, destructive recovery commands (shadow-copy deletion, log clearing), AV/EDR processes killed. A single occurrence is the signal — not rate-based like the others. |
| `DistributedSprayDetector` | CUSUM-based, keyed per **target account** rather than per source — catches a botnet spreading login attempts across many low-volume sources specifically to stay under any single source's rate limit. |
| `ReviewGate` | Fail-secure quarantine. Everything stays blocked until explicitly cleared or confirmed. Optionally persists to disk (`ReviewGate(persist_path=...)`) so pending items survive a restart. |
| `ScriptRunnerAdapter` | Turns raw script/process logs into detector events — routes all six detectors above. |
| `WindowsSecurityLogCollector` / `WindowsBruteforceAdapter` | Real telemetry: pulls actual failed-logon events from the Windows Security log (`wevtutil`, stdlib only) and feeds `BruteforceDetector`. Everything else in this table works on structured events regardless of source; this is the one path that reads live OS data. See `docs/ARCHITECTURE.md` and `examples/windows_security_log_demo.py`. |
| `IPIntelligenceProvider` / `PrivateNetworkHeuristicProvider` | Pluggable proxy/VPN/datacenter classification for `WindowsBruteforceAdapter`. Ships with a stdlib-only heuristic that separates private/internal addresses from public ones; implement the protocol against a real GeoIP/ASN source for full coverage. Defaults to reporting honest "unknown" rather than guessing. |
| `DTDAPSConfig` / `load_config` | JSON/YAML config loading — see **Configuration** below. |
| `dtdaps` CLI | `dtdaps run` / `dtdaps review` — see **CLI** above. |

All of the above is pure Python 3.9+ with **zero third-party dependencies**.

---

## Project layout

```
dtdaps/
├── engine/           # SignalSmoother, AdaptiveThreshold, AnomalyEngine
├── detectors/        # Six specialized detectors + NoveltyDetector
├── triage/           # ReviewGate
├── telemetry/        # Real OS telemetry collectors (Windows Security log) + IP intelligence
├── adapter.py
├── entity_store.py
├── config.py         # DTDAPSConfig, load_config
├── cli.py            # `dtdaps run` / `dtdaps review`
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

**A note on the math.** My background here traces back to IB Mathematics: Analysis and Approaches HL — that's where I first got comfortable with statistics, probability distributions, and the kind of rigorous reasoning this project leans on. The robust (median/MAD) and multivariate (Mahalanobis-distance) baselines added since the initial version are a direct extension of that foundation: taking the same statistical thinking and applying it to problems a single mean-and-variance model can't handle on its own.

---

## Extending it

1. Subclass `BaseDetector` and implement `ingest()` / `get_anomalies()`.
2. Use `EntityStore` + `AnomalyEngine` inside your detector.
3. Put `human_readable_summary`, `agent_action`, and `false_positive_check` in the event `context`.
4. Wire new event types into `ScriptRunnerAdapter._route()`.
5. Add baseline-then-spike tests.

See `docs/ARCHITECTURE.md` for the full contracts.

---

## Configuration

Sensitivity, sample thresholds, review-queue persistence, and the
spray detector's CUSUM parameters can live in a JSON (always) or YAML
(if `pyyaml` is installed) file instead of Python constructor
arguments:

```json
{
  "sensitivity": 3.0,
  "min_samples": 15,
  "review_gate_persist_path": "review_queue.json",
  "distributed_spray": {
    "expected_mean": 1.0,
    "slack": 0.5,
    "threshold": 10.0,
    "min_distinct_sources": 3
  }
}
```

```python
from dtdaps import load_config, ScriptRunnerAdapter

config = load_config("config.json")
adapter = ScriptRunnerAdapter.from_config(config)
```

An unrecognized key raises immediately rather than being silently
ignored — a typo'd key doing nothing is a worse failure mode than a
loud error at startup. `DefenseTamperingDetector` has no tunable
knobs (it's allowlist-based) and isn't configurable here.

---

## Logging

DTDAPS logs through the standard `logging` module under the `dtdaps.*`
logger namespace — it never calls `logging.basicConfig()` itself, since a
library configuring the root logger for you is a good way to break your
application's own logging setup. Turn it on in your own code:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

What you'll see at each level:

- **WARNING** — every anomaly `ReviewGate` blocks (`BLOCKED review_id=... entity=... detector=...`),
  plus sustained high-cardinality entity eviction (a signal `max_entities` may be too low for your traffic).
- **INFO** — human decisions on a review item (`CONFIRMED` / `CLEARED`), a persisted queue being reloaded
  on startup, and per-poll summaries from `WindowsBruteforceAdapter`.
- **ERROR** — failures that don't stop the process but you should know about: the review queue failing
  to persist to disk, or `wevtutil` failing/timing out.
- **DEBUG** — routing decisions with no matching detector, individual entity evictions, and per-fetch
  counts from the Windows collector.

The `BLOCKED` line at WARNING is the one to alert on if you're wiring this into a SIEM or log
shipper — it's the fail-secure gate's entire audit trail in one grep-able line.

---

## License

MIT. Use it for defensive and educational purposes in environments you own or are authorized to test.
