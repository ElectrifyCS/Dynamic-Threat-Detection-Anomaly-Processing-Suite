"""End-to-end demo of all four detectors + ReviewGate."""

import random
from dtdaps import (
    BruteforceDetector,
    RansomwareDetector,
    InfostealerDetector,
    KeyloggerDetector,
    ReviewGate,
)

random.seed(11)
gate = ReviewGate()

# ── Bruteforce: datacenter-proxy spray ──────────────────────────────
bf = BruteforceDetector(sensitivity=3.0, min_samples=10)
for _ in range(15):
    bf.ingest({
        "entity": "ip_10.0.0.5",
        "failed_logins_last_minute": random.choice([0, 1]),
    })
bf.ingest({
    "entity": "ip_10.0.0.5",
    "failed_logins_last_minute": 12,
    "unique_accounts_targeted": 8,
    "is_proxy_or_vpn": True,
    "asn_type": "datacenter",
})
for a in bf.get_anomalies():
    gate.submit(a)

# ── Ransomware: intermittent encryption ─────────────────────────────
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

# ── Infostealer: zero-variance credential spike ─────────────────────
inf = InfostealerDetector(sensitivity=3.0, min_samples=10, min_prior_observations=5)
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

# ── Keylogger: unauthorized hook + buffer burst ─────────────────────
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

# ── Report ──────────────────────────────────────────────────────────
pending = gate.pending()
print(f"Total pending review items: {len(pending)}\n")
for item in pending:
    print(f"[{item.event.malware_category.upper()}] {item.event.detector}")
    print(f"  {item.plain_language_reason}\n")
