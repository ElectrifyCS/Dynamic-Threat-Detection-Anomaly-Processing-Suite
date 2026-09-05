from dtdaps import ScriptRunnerAdapter
from dtdaps.detectors.lolbin_compiler_detector import LOLBinCompilerAbuseDetector


def test_normal_baseline_not_flagged():
    detector = LOLBinCompilerAbuseDetector(sensitivity=3.0, min_samples=10)
    for _ in range(15):
        detector.ingest({
            "entity": "build_server_01", "compiler_invocations_last_window": 3,
            "compiler_name": "msbuild.exe", "parent_process": "devenv.exe",
        })
    assert detector.get_anomalies() == []


def test_burst_from_scripting_host_flagged():
    # Grounded directly in the AgentTesla PS1 report: 7 aspnet_compiler.exe
    # invocations from PowerShell in one session.
    detector = LOLBinCompilerAbuseDetector(sensitivity=3.0, min_samples=10)
    for _ in range(12):
        detector.ingest({
            "entity": "host_01", "compiler_invocations_last_window": 0,
        })
    detector.ingest({
        "entity": "host_01", "compiler_invocations_last_window": 7,
        "compiler_name": "aspnet_compiler.exe", "parent_process": "powershell.exe",
    })
    anomalies = detector.get_anomalies()
    assert len(anomalies) == 1
    assert anomalies[0].detector == "lolbin_compiler_abuse"
    assert anomalies[0].context["suspicious_parent"] is True


def test_routes_through_adapter():
    adapter = ScriptRunnerAdapter()
    for _ in range(12):
        adapter.process_script_log({
            "entity": "host_02", "type": "compiler_invocation",
            "compiler_invocations_last_window": 0,
        })
    reviews = adapter.process_script_log({
        "entity": "host_02", "type": "compiler_invocation",
        "compiler_invocations_last_window": 7,
        "compiler_name": "csc.exe", "parent_process": "powershell.exe",
    })
    assert len(reviews) == 1
    assert reviews[0].event.detector == "lolbin_compiler_abuse"
