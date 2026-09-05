"""
telegram_c2_detector.py

Grounded directly in the malware behavior reports on file: FOUR of the
five analyzed samples (the RAT/loader/stealer, Snake keylogger,
guloader keylogger, and AgentTesla PowerShell stealer) all used
Telegram infrastructure for C2 or exfiltration. This isn't a
coincidence -- Telegram's Bot API has become close to a default
feature of commodity malware-as-a-service kits (AgentTesla, Xworm,
Snake are all sold/rented with it built in) specifically because it's
free, TLS-wrapped by default, and a defender can't just blanket-block
telegram.org without breaking legitimate use for everyone else.

The statistical/detection insight: it's not "this host talked to
Telegram" that matters -- legitimate Telegram Desktop traffic to that
same infrastructure is completely normal and constant. It's WHICH
PROCESS made the connection. The real Telegram client has a small,
stable set of binary names. A script host, a temp-directory-executed
binary, or a Windows-signed compiler/interpreter (csc.exe, MSBuild,
PowerShell, wscript.exe) talking to Telegram's Bot API endpoint is
something the legitimate client never does -- there's no ambiguity to
baseline away, so like DefenseTamperingDetector this is allowlist-based
and near-instant rather than rate-based.

Expected raw event shape (ingest()):
    {
        "type": "network_connection",
        "entity": "host_01",
        "process_name": "csc.exe",
        "domain": "api.telegram.org",
    }
"""

from .base_detector import BaseDetector, AnomalyEvent


class TelegramC2Detector(BaseDetector):
    # Telegram's actual Bot API endpoint -- what malware talks to.
    # Deliberately narrow: NOT the general telegram.org web/CDN
    # domains a browser might legitimately touch, just the API host
    # that bot-driven C2/exfiltration actually uses.
    _BOT_API_DOMAINS = {
        "api.telegram.org",
    }

    # The real Telegram Desktop client's own binary names. Anything
    # else contacting the Bot API domain above is the signal -- kept
    # narrow and explicit on purpose, same allowlist philosophy as
    # DefenseTamperingDetector.
    _LEGITIMATE_TELEGRAM_CLIENTS = {
        "telegram.exe",
        "telegramdesktop.exe",
        "updater.exe",  # Telegram Desktop's own auto-updater
    }

    # Processes that have essentially zero legitimate reason to be
    # the ones making this connection -- scripting hosts, compilers,
    # and interpreters commonly abused as staging/execution LOLBins
    # across the uploaded reports. Not required for a flag (ANY
    # non-allowlisted process is flagged), but noted in context to
    # sharpen the summary when it matches.
    _HIGH_CONFIDENCE_ABUSE_PROCESSES = {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "csc.exe",
        "msbuild.exe",
        "aspnet_compiler.exe",
    }

    def __init__(self):
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

    def ingest(self, event: dict) -> None:
        if event.get("type") != "network_connection":
            return

        entity = event["entity"]
        domain = event.get("domain", "").lower()
        process_name = event.get("process_name", "").lower()

        if domain not in self._BOT_API_DOMAINS:
            return
        if process_name in self._LEGITIMATE_TELEGRAM_CLIENTS:
            return

        self._history[entity] = self._history.get(entity, 0) + 1

        high_confidence = process_name in self._HIGH_CONFIDENCE_ABUSE_PROCESSES
        confidence_note = (
            f" '{process_name}' is a scripting host, compiler, or interpreter -- "
            f"one of the most common ways malware stages or executes itself, "
            f"and it has no legitimate reason to be talking to Telegram's Bot API."
            if high_confidence
            else ""
        )
        summary = (
            f"Blocked '{process_name}' on '{entity}' from contacting Telegram's Bot "
            f"API ({domain}). This isn't the real Telegram client, which has no "
            f"reason to be reached this way -- Telegram's free, TLS-wrapped Bot API "
            f"has become a near-default C2/exfiltration channel for commodity "
            f"malware-as-a-service kits precisely because it avoids the cost and "
            f"exposure of standing up dedicated infrastructure.{confidence_note}"
        )

        self._pending.append(
            AnomalyEvent(
                detector="telegram_bot_api_c2",
                malware_category="c2_communication",
                entity=entity,
                anomaly_score=0.95 if high_confidence else 0.85,
                z_score=0.0,
                raw_value=1,
                smoothed_value=1,
                context={
                    "recent_occurrences": self._history[entity],
                    "signal": "unauthorized_telegram_bot_api_contact",
                    "process_name": process_name,
                    "domain": domain,
                    "high_confidence_abuse_process": high_confidence,
                    "human_readable_summary": summary,
                    "agent_action": "pause_and_prompt_human",
                    "false_positive_check": (
                        "Pending human review to confirm this isn't a legitimate, "
                        "IT-approved internal tool that deliberately uses a Telegram "
                        "bot for notifications (e.g. a custom monitoring/alerting "
                        "script) -- rare, but not unheard of in some environments."
                    ),
                },
            )
        )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out


if __name__ == "__main__":
    detector = TelegramC2Detector()

    # legitimate: the real Telegram Desktop client
    detector.ingest({
        "type": "network_connection", "entity": "host_01",
        "process_name": "Telegram.exe", "domain": "api.telegram.org",
    })

    # the AgentTesla/PS1 stealer pattern: PowerShell exfiltrating via Telegram
    detector.ingest({
        "type": "network_connection", "entity": "host_02",
        "process_name": "powershell.exe", "domain": "api.telegram.org",
    })

    for anomaly in detector.get_anomalies():
        print(anomaly.to_dict())
