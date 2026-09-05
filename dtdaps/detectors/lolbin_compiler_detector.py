"""
lolbin_compiler_detector.py

Grounded in THREE of the five uploaded malware reports, each abusing
a different Windows-signed .NET build tool the same way: the
RAT/loader/stealer used csc.exe to compile C# at runtime, Snake
keylogger used MSBuild.exe, and the AgentTesla PowerShell stealer
invoked aspnet_compiler.exe SEVEN times in one session. All three are
the same underlying technique -- using a signed build tool to compile
or JIT-run malicious code at runtime so nothing suspicious ever lands
on disk as a standalone PE, and so the process tree shows a trusted
Microsoft binary instead of an unknown executable.

Unlike DefenseTamperingDetector's signals, this can't be an instant
allowlist flag: these tools have entirely legitimate, frequent uses
(a real dev workstation or CI/build server invokes csc.exe/MSBuild
constantly). So this is RATE-based against each entity's OWN
baseline, same design as BruteforceDetector -- a build server's high
baseline usage is normal for that specific entity; the same rate
suddenly appearing on a host with no such history, especially spawned
from a bare scripting host rather than an IDE or build orchestrator,
is the signal AgentTesla's 7-invocations-in-one-session burst would
trip.

Expected raw event shape (ingest()):
    {
        "entity": "host_01",
        "compiler_invocations_last_window": 7,
        "compiler_name": "aspnet_compiler.exe",   # optional, for context
        "parent_process": "powershell.exe",        # optional, defaults to "unknown"
    }
"""

from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from ..entity_store import EntityStore


class LOLBinCompilerAbuseDetector(BaseDetector):
    # Windows-signed build/compile tools observed being abused, across
    # the uploaded reports, to compile or JIT-run code at runtime
    # rather than dropping a standalone PE to disk. Informational only
    # (not required for detection) -- used to make the summary
    # readable.
    _KNOWN_COMPILER_LOLBINS = {
        "csc.exe": "C# compiler",
        "vbc.exe": "Visual Basic compiler",
        "msbuild.exe": "MSBuild",
        "aspnet_compiler.exe": "ASP.NET precompiler",
        "ilasm.exe": "IL assembler",
        "jsc.exe": "JScript compiler",
    }

    # A compiler launched from an IDE, build system, or CI runner is
    # ordinary. One launched from a bare scripting host is much more
    # consistent with the staging chains in the uploaded reports
    # (PowerShell -> aspnet_compiler.exe, WMI -> PowerShell -> MSBuild)
    # than a developer's normal workflow.
    _SUSPICIOUS_PARENTS = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    }

    def __init__(
        self, sensitivity: float = 3.0, min_samples: int = 15, max_entities: int = 10_000
    ):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        # bounded per-entity engines -- see entity_store.py
        self._engines = EntityStore(max_entities=max_entities)
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

    def _engine_for(self, entity: str) -> AnomalyEngine:
        return self._engines.get_or_create(
            entity,
            lambda: AnomalyEngine(
                sensitivity=self.sensitivity,
                min_samples=self.min_samples,
                stationary=False,
                decay=0.1,
            ),
        )

    def ingest(self, event: dict) -> None:
        entity = event["entity"]
        rate = event["compiler_invocations_last_window"]
        compiler_name = event.get("compiler_name", "unknown").lower()
        parent_process = event.get("parent_process", "unknown").lower()

        suspicious_parent = parent_process in self._SUSPICIOUS_PARENTS
        # A scripting host driving a compiler is weighted up front,
        # same rationale as BruteforceDetector's proxy/datacenter
        # weighting: it's a much stronger signal than the raw rate
        # alone, so it should push weaker bursts over threshold too,
        # not just scale ones that already would have tripped it.
        weighted_metric = rate * (1.8 if suspicious_parent else 1.0)

        engine = self._engine_for(entity)
        result = engine.process(weighted_metric)

        if result.is_anomaly:
            self._history[entity] = self._history.get(entity, 0) + 1
            friendly_name = self._KNOWN_COMPILER_LOLBINS.get(compiler_name, compiler_name)
            parent_note = (
                f" It was launched from '{parent_process}', a bare scripting host "
                f"rather than an IDE or build system -- not how a developer "
                f"normally invokes a compiler."
                if suspicious_parent
                else ""
            )
            summary = (
                f"Blocked unusual compiler-tool activity on '{entity}': "
                f"{friendly_name} ({compiler_name}) was invoked {rate} time(s) in "
                f"a short window, well above this entity's own baseline."
                f"{parent_note} Windows-signed build tools are increasingly abused "
                f"to compile or JIT-run malicious code at runtime so nothing "
                f"suspicious ever lands on disk as a standalone executable."
            )
            self._pending.append(
                AnomalyEvent(
                    detector="lolbin_compiler_abuse",
                    malware_category="defense_evasion",
                    entity=entity,
                    anomaly_score=result.anomaly_score,
                    z_score=result.z_score,
                    raw_value=rate,
                    smoothed_value=result.smoothed_value,
                    context={
                        "recent_occurrences": self._history[entity],
                        "baseline_rate": engine._threshold.baseline[0],
                        "compiler_name": compiler_name,
                        "parent_process": parent_process,
                        "suspicious_parent": suspicious_parent,
                        "human_readable_summary": summary,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": (
                            "Pending human review to rule out a legitimate "
                            "developer workstation, build server, or CI runner -- "
                            "this entity's OWN historical baseline is what "
                            "triggered the flag, but a sudden role change (e.g. "
                            "this host just became a build agent) can look "
                            "identical to abuse."
                        ),
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out


if __name__ == "__main__":
    detector = LOLBinCompilerAbuseDetector(sensitivity=3.0, min_samples=10)

    # normal baseline for this entity: occasional compiler use
    for _ in range(12):
        detector.ingest({
            "entity": "host_01", "compiler_invocations_last_window": 1,
            "compiler_name": "csc.exe", "parent_process": "devenv.exe",
        })

    # the AgentTesla pattern: 7 aspnet_compiler.exe invocations from PowerShell
    detector.ingest({
        "entity": "host_01", "compiler_invocations_last_window": 7,
        "compiler_name": "aspnet_compiler.exe", "parent_process": "powershell.exe",
    })

    for anomaly in detector.get_anomalies():
        print(anomaly.to_dict())
