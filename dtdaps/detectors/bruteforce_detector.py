"""
bruteforce_detector.py

Watches failed-login rates and account targeting patterns per entity (IP or User).
Supports detection of both single-account brute-force attacks and distributed
password spraying / credential stuffing, weighted further by proxy/VPN and
datacenter-ASN origin -- automated credential attacks overwhelmingly come
from hosting infrastructure, not residential connections.

Expected raw event shape (ingest()):
    {
        "entity": "ip_192.168.1.50",
        "failed_logins_last_minute": 12,
        "unique_accounts_targeted": 8,       # optional, defaults to 1
        "is_proxy_or_vpn": true,             # optional, defaults to False
        "asn_type": "datacenter"             # optional: "datacenter" | "residential" | "unknown"
    }
"""

from .base_detector import BaseDetector, AnomalyEvent
from ..engine import AnomalyEngine
from ..entity_store import EntityStore


class BruteforceDetector(BaseDetector):
    def __init__(self, sensitivity: float = 3.0, min_samples: int = 20, max_entities: int = 10_000):
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        # bounded per-entity engines -- see entity_store.py for why this
        # matters once real entity counts (many users/hosts) are in play
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

        # Datacenter/hosting-ASN origin is a much stronger automation
        # signal than "is a VPN" alone: legitimate individual users
        # essentially never connect directly from datacenter IP space,
        # whereas VPN usage by itself is common among remote workers
        # and privacy-conscious users and shouldn't be weighted as
        # heavily on its own -- weighting them separately (rather than
        # one combined flag) keeps a corporate-VPN false positive from
        # scoring the same as an actual hosting-provider botnet.
        proxy_weight = 1.0
        if is_proxy_or_vpn:
            proxy_weight *= 1.3
        if asn_type == "datacenter":
            proxy_weight *= 1.7

        weighted_metric = rate * spray_weight * proxy_weight

        engine = self._engine_for(entity)
        result = engine.process(weighted_metric)

        if result.is_anomaly:
            self._history[entity] = self._history.get(entity, 0) + 1
            is_spray = unique_accounts > 3
            origin_note = ""
            if asn_type == "datacenter":
                origin_note = " The traffic originated from datacenter/hosting infrastructure, not a residential connection -- a strong indicator of automated tooling rather than a person typing."
            elif is_proxy_or_vpn:
                origin_note = " The traffic originated through a proxy or VPN."

            if is_spray:
                summary_str = (
                    f"Blocked a distributed login attack. Entity '{entity}' attempted to log in "
                    f"using common passwords across {unique_accounts} distinct user accounts."
                    f"{origin_note}"
                )
            else:
                summary_str = (
                    f"Blocked a brute-force attack. Entity '{entity}' triggered a high volume "
                    f"({rate}) of failed logins targeting a single account in a very short "
                    f"time window.{origin_note}"
                )

            false_positive_note = "Pending human review to rule out a misconfigured script or a user repeatedly failing multi-factor authentication."
            if is_proxy_or_vpn and asn_type != "datacenter":
                false_positive_note += " Note: VPN usage alone is common among remote employees -- weigh this alongside the rate/spray signal, not as standalone proof."

            self._pending.append(
                AnomalyEvent(
                    detector="bruteforce_spray_rate" if is_spray else "bruteforce_login_rate",
                    malware_category="bruteforce",
                    entity=entity,
                    anomaly_score=result.anomaly_score,
                    z_score=result.z_score,
                    raw_value=rate,
                    smoothed_value=result.smoothed_value,
                    context={
                        "recent_occurrences": self._history[entity],
                        "baseline_rate": engine._threshold.baseline[0],
                        "unique_accounts_targeted": unique_accounts,
                        "attack_type": "password_spraying" if is_spray else "credential_bruteforce",
                        "is_proxy_or_vpn": is_proxy_or_vpn,
                        "asn_type": asn_type,
                        "proxy_weight_applied": round(proxy_weight, 2),
                        "human_readable_summary": summary_str,
                        "agent_action": "pause_and_prompt_human",
                        "false_positive_check": false_positive_note,
                    },
                )
            )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out


if __name__ == "__main__":
    import random

    detector = BruteforceDetector(sensitivity=3.0, min_samples=10)

    # normal baseline traffic for this IP
    for _ in range(15):
        detector.ingest({"entity": "ip_192.168.1.50", "failed_logins_last_minute": random.choice([0, 1])})

    # the uploaded sample: spray attempt from a datacenter-hosted proxy/VPN
    detector.ingest({
        "entity": "ip_192.168.1.50",
        "failed_logins_last_minute": 12,
        "unique_accounts_targeted": 8,
        "is_proxy_or_vpn": True,
        "asn_type": "datacenter",
    })

    for anomaly in detector.get_anomalies():
        print(anomaly.to_dict())
