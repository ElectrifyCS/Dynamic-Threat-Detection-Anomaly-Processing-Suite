from dtdaps import ScriptRunnerAdapter
from dtdaps.detectors.mutex_fanout_detector import MutexFanoutDetector


def test_single_identity_not_flagged():
    detector = MutexFanoutDetector()
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Temp\exe.exe",
    })
    assert detector.get_anomalies() == []


def test_second_distinct_identity_flags():
    # Grounded directly in the diskdiag.exe RAT report: same mutex,
    # two distinct process identities on the same host.
    detector = MutexFanoutDetector()
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Users\admin\AppData\Local\Temp\exe.exe",
    })
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })
    anomalies = detector.get_anomalies()
    assert len(anomalies) == 1
    assert anomalies[0].detector == "mutex_fanout_masquerading"
    assert anomalies[0].context["distinct_identity_count"] == 2


def test_same_identity_repeated_not_flagged():
    detector = MutexFanoutDetector()
    for _ in range(5):
        detector.ingest({
            "entity": "host_01", "mutex_name": "DSYS",
            "process_name": "exe.exe", "process_path": r"C:\Temp\exe.exe",
        })
    assert detector.get_anomalies() == []


def test_different_hosts_do_not_cross_contaminate():
    detector = MutexFanoutDetector()
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Temp\exe.exe",
    })
    detector.ingest({
        "entity": "host_02", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })
    assert detector.get_anomalies() == []


def test_does_not_re_alert_on_further_events_for_same_pair():
    detector = MutexFanoutDetector()
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Temp\exe.exe",
    })
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })
    assert len(detector.get_anomalies()) == 1
    detector.ingest({
        "entity": "host_01", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })
    assert detector.get_anomalies() == []


def test_routes_through_adapter():
    adapter = ScriptRunnerAdapter()
    adapter.process_script_log({
        "entity": "host_01", "type": "mutex_created", "mutex_name": "DSYS",
        "process_name": "exe.exe", "process_path": r"C:\Temp\exe.exe",
    })
    reviews = adapter.process_script_log({
        "entity": "host_01", "type": "mutex_created", "mutex_name": "DSYS",
        "process_name": "diskdiag.exe", "process_path": r"C:\Windows\Temp\diskdiag.exe",
    })
    assert len(reviews) == 1
    assert reviews[0].event.detector == "mutex_fanout_masquerading"
