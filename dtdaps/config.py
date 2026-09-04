"""
Configuration file loading for DTDAPS.

Every detector's tuning knobs are Python constructor arguments today,
which means changing a threshold means editing code and redeploying.
This module loads a small, explicit config schema from JSON (always
available, stdlib-only) or YAML (if PyYAML happens to be installed)
so those knobs can live in a file instead.

Example config.json:

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

`sensitivity` / `min_samples` apply to the four z-score-based detectors
(Keylogger, Infostealer, Ransomware, Bruteforce) via `ScriptRunnerAdapter`.
`DefenseTamperingDetector` has no tunable knobs (allowlist-based) and
isn't configurable here. `distributed_spray` maps onto
`DistributedSprayDetector`'s CUSUM parameters, which are on a
different, incompatible scale from `sensitivity` and so get their own
namespace rather than reusing the top-level keys.

An unrecognized key raises immediately rather than being silently
ignored — a typo'd key doing nothing at all is a worse failure mode
than a loud error at startup.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import json

_KNOWN_KEYS = {
    "sensitivity",
    "min_samples",
    "review_gate_persist_path",
    "distributed_spray",
}
_KNOWN_SPRAY_KEYS = {"expected_mean", "slack", "threshold", "min_distinct_sources"}


@dataclass
class DistributedSprayConfig:
    expected_mean: float = 1.0
    slack: float = 0.5
    threshold: float = 10.0
    min_distinct_sources: int = 3


@dataclass
class DTDAPSConfig:
    sensitivity: float = 2.5
    min_samples: int = 10
    review_gate_persist_path: Optional[str] = None
    distributed_spray: DistributedSprayConfig = field(
        default_factory=DistributedSprayConfig
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DTDAPSConfig":
        if not isinstance(data, dict):
            raise ValueError("Config must be a mapping/object at the top level.")

        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            raise ValueError(
                f"Unknown config key(s): {sorted(unknown)}. "
                f"Known top-level keys: {sorted(_KNOWN_KEYS)}."
            )

        spray_data = data.get("distributed_spray") or {}
        if not isinstance(spray_data, dict):
            raise ValueError("'distributed_spray' must be a mapping/object.")
        unknown_spray = set(spray_data) - _KNOWN_SPRAY_KEYS
        if unknown_spray:
            raise ValueError(
                f"Unknown distributed_spray config key(s): {sorted(unknown_spray)}. "
                f"Known keys: {sorted(_KNOWN_SPRAY_KEYS)}."
            )

        try:
            return cls(
                sensitivity=float(data.get("sensitivity", 2.5)),
                min_samples=int(data.get("min_samples", 10)),
                review_gate_persist_path=data.get("review_gate_persist_path"),
                distributed_spray=DistributedSprayConfig(**spray_data),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid config value: {exc}") from exc


def load_config(path: str) -> DTDAPSConfig:
    """Load a DTDAPSConfig from a .json, .yaml, or .yml file."""
    p = Path(path)
    suffix = p.suffix.lower()

    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    if suffix == ".json":
        with open(p, "r") as f:
            data = json.load(f)
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "Loading a .yaml/.yml config requires PyYAML "
                "('pip install pyyaml'). Use a .json config instead if "
                "you'd rather not add the dependency — DTDAPS itself "
                "stays stdlib-only either way."
            ) from exc
        with open(p, "r") as f:
            data = yaml.safe_load(f) or {}
    else:
        raise ValueError(
            f"Unrecognized config file extension {suffix!r} for {path}. "
            "Use .json, .yaml, or .yml."
        )

    return DTDAPSConfig.from_dict(data)
