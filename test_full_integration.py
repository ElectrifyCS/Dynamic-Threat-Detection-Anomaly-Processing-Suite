"""End-to-end smoke test for all four detectors + ReviewGate."""

import random
import sys
from pathlib import Path

# Allow running without install
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dtdaps import (
    BruteforceDetector,
    RansomwareDetector,
    InfostealerDetector,
    KeyloggerDetector,
    ReviewGate,
)


def test_all_detectors_fire():
    random.seed(11)
    gate = ReviewGate()

    # Bruteforce
    bf = BruteforceDetector(sensitivity=3.0, min_samples=10)
    for _ in range(15):
        bf.ingest({"entity": "ip_10.0.0.5", "failed_logins_last_minute": random.choice([0, 1])})
    bf.ingest({
        "entity": "ip_10.0.0.5",
        "failed_logins_last_minute": 12,
        "unique_accounts_targeted": 8,
        "is_proxy_or_vpn": True,
        "asn_type": "datacenter",
    })
    for a in bf.get_anomalies():
        gate.submit(a)

    # Ransomware
    rw = RansomwareDetector(sensitivity=3.0, min_samples=10)
    for _ in range(15):
        rw.ingest({
            "entity": "host_02",
            "files_modified_last_minute": random.choice([1, 2]),
            "avg_entropy_delta": 0.05,
        })
    rw.ingest({
        "entity": "host_02",
        "files_modified_last_minute": 20,
        "avg_entropy_delta": 0.4,
    })
    for a in rw.get_anomalies():
        gate.submit(a)

    # Infostealer (zero-variance case)
    inf = InfostealerDetector(sensitivity=3.0, min_samples=10)
    for _ in range(15):
        inf.ingest({
            "type": "credential_access",
            "entity": "proc_99",
            "sensitive_path_reads_last_minute": 0,
        })
    inf.ingest({
        "type": "credential_access",
        "entity": "proc_99",
        "sensitive_path_reads_last_minute": 8,
        "file_types": ["wallet.dat"],
    })
    for a in inf.get_anomalies():
        gate.submit(a)

    # Keylogger
    kl = KeyloggerDetector(sensitivity=3.0, min_samples=10)
    for _ in range(15):
        kl.ingest({
            "type": "buffer_write",
            "entity": "proc_77",
            "writes_last_minute": random.choice([0, 1]),
        })
    kl.ingest({
        "type": "keyboard_hook_installed",
        "entity": "proc_77",
        "process_name": "svc_update.exe",
    })
    kl.ingest({
        "type": "buffer_write",
        "entity": "proc_77",
        "writes_last_minute": 25,
    })
    for a in kl.get_anomalies():
        gate.submit(a)

    pending = gate.pending()
    assert len(pending) >= 4, f"Expected ≥4 flags, got {len(pending)}"
    categories = {i.event.malware_category for i in pending}
    assert "bruteforce" in categories
    assert "ransomware" in categories
    assert "infostealer" in categories
    assert "keylogger" in categories
    print(f"OK — {len(pending)} pending items across {categories}")


if __name__ == "__main__":
    test_all_detectors_fire()
