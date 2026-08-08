"""Minimal AnomalyEngine demo — no detectors required."""

from dtdaps import AnomalyEngine

engine = AnomalyEngine(sensitivity=3.0, min_samples=10, decay=0.1)

print("Feeding normal values…")
for v in [1, 2, 1, 2, 3, 1, 2, 2, 1, 2, 1, 2]:
    r = engine.process(v)
    print(f"  value={v:4.1f}  z={r.z_score:6.2f}  anomaly={r.is_anomaly}")

print("\nFeeding a spike…")
r = engine.process(25)
print(f"  value=25.0  z={r.z_score:6.2f}  score={r.anomaly_score:.3f}  anomaly={r.is_anomaly}")
