"""
defense_tampering_detector.py

Cross-cutting detector, not tied to one malware family -- built from
a pattern that showed up independently in THREE of the four malware
analyses (RedLine, smrtiLog keylogger, ransomware): disabling
security tools is a near-universal early-stage move, not something
exclusive to any one category. Rather than duplicate similar
allowlist logic inside four separate detectors, this is its own
detector that any category's incident can also trigger.

Three signals, all binary/allowlist-based (near-instant, max-
confidence) rather than rate-based -- like the LummaC2 hash check,
almost none of these have a legitimate reason to happen at all,
so a single occurrence is the signal, not a rate of occurrences:

1. Critical security service stopped -- WinDefend, Tamper Protection,
   Windows Update services (wuauserv/WaaSMedicSvc). From RedLine's
   feedback: escalates to TrustedInstaller/Administrator specifically
   to disable these.

2. Destructive recovery command detected -- shadow copy deletion
   (`vssadmin delete shadows`), backup catalog deletion, boot
   recovery disabling. From the ransomware feedback: "deleting volume
   shadow copies... to blind security teams" -- about as close to a
   guaranteed-malicious command as exists in Windows.

3. Security process terminated -- AV/EDR process killed. From the
   keylogger feedback: "Antivirus Termination: identifying and
   shutting down known security software processes."

Two more signals added from a later RAT/diskdiag.exe report and the
guloader keylogger report, same allowlist philosophy:

4. Security-relevant registry key tampered -- covers two distinct
   patterns bundled together because both are "critical system
   registry key hijacked" rather than a rate/behavior question:
   (a) Defender/AV disable keys (DisableAntiSpyware,
   DisableRealtimeMonitoring, etc.), matching the diskdiag.exe
   report's "Found strings related to reading or modifying Windows
   Defender settings"; (b) the Winlogon Userinit/Shell/Notify keys,
   matching that same report's "Changes the login/logoff helper path
   in the registry" -- a classic persistence-via-critical-key hijack
   (T1547.004). Its primary purpose is persistence rather than
   blinding defenses, but it's included here rather than a separate
   detector because the detection question is identical: "was one of
   a short list of critical system registry keys touched at all,"
   the same shape as the destructive-command check above.

5. UAC-bypass-capable LOLBin invoked -- from the guloader keylogger
   report's "used cmstp.exe for UAC bypass." A short allowlist of
   binaries with well-documented UAC-bypass techniques
   (cmstp.exe, fodhelper.exe, eventvwr.exe, sdclt.exe, computerdefaults.exe).

Expected raw event shapes (ingest() accepts any):
    {"type": "security_service_stopped", "entity": "host_01",
     "service_name": "WinDefend"}

    {"type": "destructive_command_detected", "entity": "host_01",
     "command": "vssadmin delete shadows /all /quiet"}

    {"type": "security_process_terminated", "entity": "host_01",
     "process_name": "MsMpEng.exe"}

    {"type": "security_setting_tampering", "entity": "host_01",
     "registry_key": "HKLM\\...\\Windows Defender\\DisableAntiSpyware"}

    {"type": "uac_bypass_lolbin", "entity": "host_01",
     "process_name": "cmstp.exe"}
"""

from .base_detector import BaseDetector, AnomalyEvent


class DefenseTamperingDetector(BaseDetector):
    def __init__(self):
        self._history: dict[str, int] = {}
        self._pending: list[AnomalyEvent] = []

        # Critical services with essentially no legitimate reason for
        # an ordinary process to stop them. Narrow and explicit on
        # purpose -- expand deliberately, don't default-allow.
        self._critical_services = {
            "windefend": "Windows Defender Antivirus",
            "wscsvc": "Windows Security Center",
            "securityhealthservice": "Windows Security Health Service",
            "sense": "Windows Defender Advanced Threat Protection",
            "wuauserv": "Windows Update",
            "waasmedicsvc": "Windows Update Medic Service",
        }

        # Substring match against the command line -- destructive
        # recovery/backup commands. Kept as literal command fragments
        # rather than a full parser: these are well-known, stable
        # command patterns, and a substring match is enough signal
        # without needing to fully parse arbitrary shell syntax.
        self._destructive_command_patterns = {
            "vssadmin delete shadows": "shadow copy deletion (removes ransomware recovery point)",
            "wmic shadowcopy delete": "shadow copy deletion via WMIC (removes ransomware recovery point)",
            "bcdedit /set {default} recoveryenabled no": "disables Windows recovery/repair boot option",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures": "disables Windows failure-boot recovery prompts",
            "wbadmin delete catalog": "deletes local Windows backup catalog",
            "wevtutil cl": "clears a Windows event log (erases forensic evidence)",
            "clear-eventlog": "clears a Windows event log via PowerShell (erases forensic evidence)",
        }

        # Process name fragments recognized as security/AV/EDR
        # software. Not exhaustive -- extend as needed, same
        # allowlist-narrowness principle as the keylogger hook check.
        self._security_process_names = {
            "msmpeng.exe": "Windows Defender",
            "mssense.exe": "Microsoft Defender for Endpoint",
            "ccsvchst.exe": "Symantec/Norton",
            "avastsvc.exe": "Avast",
            "avp.exe": "Kaspersky",
            "egui.exe": "ESET",
        }

        # Substring match against a registry key path. Two distinct
        # concerns bundled here on purpose -- see module docstring
        # signal #4: Defender/AV disable keys, and the Winlogon
        # persistence-hijack keys from the diskdiag.exe report.
        self._critical_registry_key_patterns = {
            "windows defender\\disableantispyware": "disables Windows Defender entirely via policy key",
            "windows defender\\real-time protection\\disablerealtimemonitoring": "disables Defender real-time protection",
            "windows defender\\disablebehaviormonitoring": "disables Defender behavior monitoring",
            "winlogon\\userinit": "hijacks the Winlogon Userinit key (persistence: runs at every logon)",
            "winlogon\\shell": "hijacks the Winlogon Shell key (persistence: replaces/rides alongside explorer.exe)",
            "winlogon\\notify": "hijacks a Winlogon Notify package (persistence: runs on logon/logoff events)",
        }

        # Binaries with well-documented UAC-bypass techniques --
        # invoking one at all (outside a handful of legitimate admin
        # contexts) is the signal. From the guloader keylogger
        # report's use of cmstp.exe.
        self._uac_bypass_lolbins = {
            "cmstp.exe": "CMSTP UAC bypass (malicious INF profile auto-elevates)",
            "fodhelper.exe": "fodhelper.exe registry-hijack UAC bypass",
            "eventvwr.exe": "eventvwr.exe mscfile registry-hijack UAC bypass",
            "sdclt.exe": "sdclt.exe UAC bypass",
            "computerdefaults.exe": "computerdefaults.exe registry-hijack UAC bypass",
        }

    def ingest(self, event: dict) -> None:
        entity = event["entity"]
        event_type = event.get("type")

        if event_type == "security_service_stopped":
            self._ingest_service_stopped(entity, event)
        elif event_type == "destructive_command_detected":
            self._ingest_destructive_command(entity, event)
        elif event_type == "security_process_terminated":
            self._ingest_process_terminated(entity, event)
        elif event_type == "security_setting_tampering":
            self._ingest_registry_tampering(entity, event)
        elif event_type == "uac_bypass_lolbin":
            self._ingest_uac_bypass(entity, event)

    def _flag(self, entity: str, detector: str, summary: str, context_extra: dict) -> None:
        self._history[entity] = self._history.get(entity, 0) + 1
        self._pending.append(
            AnomalyEvent(
                detector=detector,
                malware_category="defense_tampering",
                entity=entity,
                anomaly_score=0.97,
                z_score=0.0,
                raw_value=1,
                smoothed_value=1,
                context={
                    "recent_occurrences": self._history[entity],
                    "human_readable_summary": summary,
                    "agent_action": "pause_and_prompt_human",
                    **context_extra,
                },
            )
        )

    def _ingest_service_stopped(self, entity: str, event: dict) -> None:
        service_name = event.get("service_name", "")
        key = service_name.lower()
        if key not in self._critical_services:
            return

        friendly_name = self._critical_services[key]
        summary = (
            f"Blocked an attempt by '{entity}' to stop {friendly_name} ({service_name}). "
            f"Legitimate software essentially never has a reason to stop this service -- "
            f"this is a common early-stage move to blind security tooling before further "
            f"malicious activity."
        )
        self._flag(
            entity,
            "defense_tampering_service_stopped",
            summary,
            {
                "signal": "security_service_stopped",
                "service_name": service_name,
                "note": f"critical security/update service ({friendly_name}) stopped",
                "false_positive_check": (
                    "Pending human review to confirm this isn't a legitimate IT-managed "
                    "service change (e.g. scheduled maintenance, a managed AV migration)."
                ),
            },
        )

    def _ingest_destructive_command(self, entity: str, event: dict) -> None:
        command = event.get("command", "")
        lowered = command.lower()

        matched_pattern = None
        matched_description = None
        for pattern, description in self._destructive_command_patterns.items():
            if pattern in lowered:
                matched_pattern = pattern
                matched_description = description
                break

        if matched_pattern is None:
            return

        summary = (
            f"Blocked '{entity}' from running a command matching a known destructive "
            f"pattern: {matched_description}. This class of command has very few "
            f"legitimate uses outside of deliberate, planned system administration."
        )
        self._flag(
            entity,
            "defense_tampering_destructive_command",
            summary,
            {
                "signal": "destructive_command_detected",
                "command": command,
                "matched_pattern": matched_pattern,
                "note": matched_description,
                "false_positive_check": (
                    "Pending human review to confirm this isn't a deliberate, "
                    "authorized administrative action (e.g. planned backup rotation, "
                    "documented recovery-partition reconfiguration)."
                ),
            },
        )

    def _ingest_process_terminated(self, entity: str, event: dict) -> None:
        process_name = event.get("process_name", "").lower()
        if process_name not in self._security_process_names:
            return

        friendly_name = self._security_process_names[process_name]
        summary = (
            f"Blocked '{entity}' from terminating {friendly_name} ({process_name}). "
            f"A running process forcefully killing security/AV software is a strong, "
            f"high-confidence signal of active malicious activity attempting to blind "
            f"defenses."
        )
        self._flag(
            entity,
            "defense_tampering_security_process_killed",
            summary,
            {
                "signal": "security_process_terminated",
                "process_name": process_name,
                "note": f"security software process ({friendly_name}) terminated",
                "false_positive_check": (
                    "Pending human review to rule out a legitimate AV uninstall/upgrade "
                    "in progress."
                ),
            },
        )

    def _ingest_registry_tampering(self, entity: str, event: dict) -> None:
        registry_key = event.get("registry_key", "")
        lowered = registry_key.lower()

        matched_pattern = None
        matched_description = None
        for pattern, description in self._critical_registry_key_patterns.items():
            if pattern in lowered:
                matched_pattern = pattern
                matched_description = description
                break

        if matched_pattern is None:
            return

        summary = (
            f"Blocked '{entity}' from tampering with a critical system registry "
            f"key: {matched_description}. This class of key has very few "
            f"legitimate reasons to be modified outside deliberate, planned "
            f"administration."
        )
        self._flag(
            entity,
            "defense_tampering_registry_key",
            summary,
            {
                "signal": "security_setting_tampering",
                "registry_key": registry_key,
                "matched_pattern": matched_pattern,
                "note": matched_description,
                "false_positive_check": (
                    "Pending human review to confirm this isn't a deliberate, "
                    "authorized administrative action (e.g. a managed AV "
                    "migration or a documented shell-replacement deployment)."
                ),
            },
        )

    def _ingest_uac_bypass(self, entity: str, event: dict) -> None:
        process_name = event.get("process_name", "").lower()
        if process_name not in self._uac_bypass_lolbins:
            return

        description = self._uac_bypass_lolbins[process_name]
        summary = (
            f"Blocked '{entity}' from invoking {process_name}, a binary with a "
            f"well-documented UAC-bypass technique: {description}. Legitimate "
            f"day-to-day use of this binary is rare enough that its invocation "
            f"alone is a strong signal, independent of any specific arguments."
        )
        self._flag(
            entity,
            "defense_tampering_uac_bypass",
            summary,
            {
                "signal": "uac_bypass_lolbin",
                "process_name": process_name,
                "note": description,
                "false_positive_check": (
                    "Pending human review to rule out a legitimate admin task "
                    "that happens to use this binary directly (uncommon, but "
                    "possible for CMSTP-based VPN profile deployment, for "
                    "example)."
                ),
            },
        )

    def get_anomalies(self) -> list[AnomalyEvent]:
        out, self._pending = self._pending, []
        return out
