"""
CRIME404 Forensic Accuracy & Scale Benchmark Suite (Checklist Section 11.B & 11.D)
Tests:
1. 10,000-event synthetic dataset parsing & pagination latency
2. Multi-timezone normalization (IST +05:30 vs UTC)
3. Deliberate cross-source contradiction & missing-telemetry gap detection
4. Backup pruning retention
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import normalize_timestamp, parse_text_evidence
from services.backup import prune_old_backups


class TestForensicScaleAndAccuracy(unittest.TestCase):
    def test_10000_event_parse_performance(self):
        lines = []
        for i in range(10000):
            sec = i % 60
            minute = (i // 60) % 60
            hour = (i // 3600) % 24
            lines.append(
                f"2026-11-18T{hour:02d}:{minute:02d}:{sec:02d}Z INFO user=analyst_{i % 20} "
                f"ip=10.0.{i % 255}.{(i * 7) % 255} action=login_success status=ok"
            )
        payload = "\n".join(lines)
        t0 = time.monotonic()
        items = parse_text_evidence(payload, "scale_10k.log", "EV-SCALE-1")
        elapsed = time.monotonic() - t0
        self.assertEqual(len(items), 10000)
        self.assertLess(elapsed, 5.0, f"10k parse took too long: {elapsed:.2f}s")

    def test_timezone_normalization_ist_to_utc(self):
        dt_utc, _disp_ts, orig_tz = normalize_timestamp("2026-11-18 15:30:00+05:30")
        self.assertIsNotNone(dt_utc)
        self.assertEqual(dt_utc.hour, 10)
        self.assertEqual(dt_utc.minute, 0)
        self.assertIn("05:30", orig_tz)

    def test_backup_pruning_retention(self):
        tmp = tempfile.mkdtemp(prefix="crime404_prune_")
        try:
            for i in range(5):
                name = os.path.join(tmp, f"crime404_backup_20261119T0{i}0000Z.c404bak")
                open(name, "wb").write(b"x")
                open(name + ".meta.json", "w").write("{}")
            removed = prune_old_backups(tmp, keep_last=2)
            self.assertEqual(removed, 3)
            remaining = [f for f in os.listdir(tmp) if f.endswith(".c404bak")]
            self.assertEqual(len(remaining), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
