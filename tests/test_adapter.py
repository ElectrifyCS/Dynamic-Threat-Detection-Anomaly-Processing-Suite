"""
Tests for ScriptRunnerAdapter, in particular its event-type routing.

Before this file existed, the adapter had zero direct test coverage --
each individual detector was tested on its own, but nothing verified
that _route() actually wires a given event_type to the right detector
with the right payload shape. That gap is exactly how
DefenseTamperingDetector and DistributedSprayDetector ended up fully
built, tested at the unit level, and still completely unreachable
through the adapter: nothing here would have caught it.
"""

from dtdaps import ScriptRunnerAdapter


def test_routes_defense_tampering_known_critical_service():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_01",
            "type": "security_service_stopped",
            "service_name": "WinDefend",
        }
    )
    assert len(reviews) == 1
    assert reviews[0].event.detector == "defense_tampering_service_stopped"
    assert reviews[0].event.malware_category == "defense_tampering"
    assert reviews[0].blocked is True


def test_routes_defense_tampering_ignores_unknown_service():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_01",
            "type": "security_service_stopped",
            "service_name": "SomeHarmlessPrintSpooler",
        }
    )
    assert reviews == []


def test_routes_defense_tampering_destructive_command():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_02",
            "type": "destructive_command_detected",
            "command": "vssadmin delete shadows /all /quiet",
        }
    )
    assert len(reviews) == 1
    assert reviews[0].event.detector == "defense_tampering_destructive_command"


def test_routes_defense_tampering_security_process_terminated():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_03",
            "type": "security_process_terminated",
            "process_name": "MsMpEng.exe",
        }
    )
    assert len(reviews) == 1
    assert reviews[0].event.detector == "defense_tampering_security_process_killed"


def test_routes_defense_tampering_registry_key_tampering():
    # Grounded in the diskdiag.exe RAT report: Winlogon Userinit hijack.
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_06",
            "type": "security_setting_tampering",
            "registry_key": r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        }
    )
    assert len(reviews) == 1
    assert reviews[0].event.detector == "defense_tampering_registry_key"


def test_registry_key_tampering_ignores_unrelated_keys():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_06",
            "type": "security_setting_tampering",
            "registry_key": r"HKCU\Software\SomeHarmlessApp\Settings",
        }
    )
    assert reviews == []


def test_routes_defense_tampering_uac_bypass():
    # Grounded in the guloader keylogger report: cmstp.exe UAC bypass.
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_07",
            "type": "uac_bypass_lolbin",
            "process_name": "cmstp.exe",
        }
    )
    assert len(reviews) == 1
    assert reviews[0].event.detector == "defense_tampering_uac_bypass"


def test_uac_bypass_ignores_unrelated_binaries():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {
            "entity": "host_07",
            "type": "uac_bypass_lolbin",
            "process_name": "notepad.exe",
        }
    )
    assert reviews == []


def test_routes_distributed_spray_across_many_sources():
    adapter = ScriptRunnerAdapter()
    reviews = []
    sources = [f"ip_10.0.0.{i}" for i in range(1, 9)]
    for _ in range(6):
        for src in sources:
            reviews.extend(
                adapter.process_script_log(
                    {
                        "type": "distributed_login_attempt",
                        "target_account": "admin@example.com",
                        "source_entity": src,
                        "failed_attempts": 2,
                    }
                )
            )
    assert len(reviews) >= 1
    alert = reviews[-1]
    assert alert.event.detector == "distributed_spray_cusum"
    assert alert.event.entity == "admin@example.com"
    assert alert.event.context["distinct_sources"] >= 3


def test_distributed_spray_too_few_sources_does_not_alert():
    adapter = ScriptRunnerAdapter()
    reviews = []
    # Only 2 distinct sources -- below min_distinct_sources default of 3,
    # so even sustained pressure should never surface as a review.
    for _ in range(20):
        for src in ["ip_10.0.0.1", "ip_10.0.0.2"]:
            reviews.extend(
                adapter.process_script_log(
                    {
                        "type": "distributed_login_attempt",
                        "target_account": "admin@example.com",
                        "source_entity": src,
                        "failed_attempts": 2,
                    }
                )
            )
    assert reviews == []


def test_unmapped_event_type_produces_no_review():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log(
        {"entity": "host_04", "type": "some_unrecognized_event"}
    )
    assert reviews == []


def test_missing_event_type_is_skipped_not_raised():
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log({"entity": "host_05"})
    assert reviews == []
