"""
Bruteforce / password-spraying signals.

Weights failed-login rate by:
  - unique accounts targeted (spray detection)
  - proxy/VPN presence
  - datacenter ASN origin (stronger automation signal than VPN alone)
"""

from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from ..entity_store import EntityStore


class BruteforceDetector(BaseDetector):
    def __init__(
        self,
        sensitivity: float = 3.0,
        min_samples: int = 20,
        max_entities: int = 10_000,
    ):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
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
        rate = event["failed_logins_last_minute"]
        unique_accounts = event.get("unique_accounts_targeted", 1)
        is_proxy_or_vpn = event.get("is_proxy_or_vpn", False)
        asn_type = event.get("asn_type", "unknown")

        spray_weight = 1.0 + (0.5 * max(0, unique_accounts - 1))

        # Datacenter origin is a stronger automation signal than VPN alone.
        proxy_weight = 1.0
        if is_proxy_or_vpn:
            proxy_weight *= 1.3
        if asn_type == "datacenter":
            proxy_weight *= 1.7

        weighted = rate * spray_weight * proxy_weight
        engine = self._engine_for(entity)
        result = engine.process(weighted)

        if result.is_anomaly:
            self._history[entity] = self._history.get(entity, 0) + 1
            is_spray = unique_accounts > 3

            origin_note = ""
            if asn_type == "datacenter":
                origin_note = (
                    " Traffic originated from datacenter/hosting infrastructure, "
                    "not a residential connection — a strong indicator of automated tooling."
                )
            elif is_proxy_or_vpn:
                origin_note = " Traffic arrived via proxy/VPN."

            if is_spray:
                summary = (
                    f"Blocked password-spraying activity from '{entity}'. "
                    f"{rate} failed logins/min across {unique_accounts} accounts."
                    f"{origin_note}"
                )
                attack_type = "password_spraying"
            else:
                summary = (
                    f"Blocked high failed-login rate from '{entity}' "
                    f"({rate}/min against baseline {engine.baseline_mean:.1f}/min)."
                    f"{origin_note}"
                )
                attack_type = "single_account_bruteforce"

            fp_note = (
                "Consider MFA lockouts or a misconfigured monitoring script "
                "before treating as a hard block."
            )
            if is_proxy_or_vpn and asn_type != "datacenter":
                fp_note += " VPN-only origin is common among remote workers."

            self._pending.append(
                AnomalyEvent(
                    detector="bruteforce_login_rate",
                    malware_category="bruteforce",
                    entity=entity,
                    anomaly_score=result.anomaly_score,
                    z_score=result.z_score,
                    raw_value=result.raw_value,
                    smoothed_value=result.smoothed_value,
                    context={
                        "signal": "failed_login_rate",
                        "attack_type": attack_type,
                        "unique_accounts_targeted": unique_accounts,
                        "is_proxy_or_vpn": is_proxy_or_vpn,
                        "asn_type": asn_type,
                        "recent_occurrences": self._history[entity],
                        "baseline_rate": engine.baseline_mean,
                        "human_readable_summary": summary,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": fp_note,
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out
