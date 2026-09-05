from dtdaps import ScriptRunnerAdapter
from dtdaps.detectors.telegram_c2_detector import TelegramC2Detector


def test_legitimate_telegram_client_not_flagged():
    detector = TelegramC2Detector()
    detector.ingest({
        "type": "network_connection", "entity": "host_01",
        "process_name": "Telegram.exe", "domain": "api.telegram.org",
    })
    assert detector.get_anomalies() == []


def test_non_client_process_flagged():
    detector = TelegramC2Detector()
    detector.ingest({
        "type": "network_connection", "entity": "host_01",
        "process_name": "csc.exe", "domain": "api.telegram.org",
    })
    anomalies = detector.get_anomalies()
    assert len(anomalies) == 1
    assert anomalies[0].detector == "telegram_bot_api_c2"
    assert anomalies[0].context["high_confidence_abuse_process"] is True


def test_non_bot_api_domain_ignored():
    detector = TelegramC2Detector()
    detector.ingest({
        "type": "network_connection", "entity": "host_01",
        "process_name": "csc.exe", "domain": "web.telegram.org",
    })
    assert detector.get_anomalies() == []


def test_wrong_event_type_ignored():
    detector = TelegramC2Detector()
    detector.ingest({
        "type": "file_modification", "entity": "host_01",
        "process_name": "csc.exe", "domain": "api.telegram.org",
    })
    assert detector.get_anomalies() == []


def test_routes_agenttesla_pattern_through_adapter():
    # Grounded directly in the PS1/AgentTesla report: PowerShell exfiltrating via Telegram.
    adapter = ScriptRunnerAdapter()
    reviews = adapter.process_script_log({
        "entity": "host_03", "type": "network_connection",
        "process_name": "powershell.exe", "domain": "api.telegram.org",
    })
    assert len(reviews) == 1
    assert reviews[0].event.malware_category == "c2_communication"
