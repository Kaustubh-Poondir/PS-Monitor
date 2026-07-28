"""
tests/test_crawler.py
Unit tests for the Crawler deduplication engine.
Tests the fingerprinting logic and deduplication behaviour
without needing a real running system.
"""

import unittest
import hashlib
import time
import threading
from unittest.mock import MagicMock, patch


# ── Helper: build a fake ProcessEvaluation ─────────────────────────────────

class FakeEval:
    def __init__(self, pid, name, level, score, alerts, started_at="2026-01-01 00:00:00",
                 username="user", exe="/usr/bin/test"):
        self.pid        = pid
        self.name       = name
        self.level      = level
        self.score      = score
        self.alerts     = alerts
        self.started_at = started_at
        self.username   = username
        self.exe        = exe


# ── Tests ──────────────────────────────────────────────────────────────────

class TestFingerprintLogic(unittest.TestCase):
    """Test SHA-256 fingerprinting is correct and consistent."""

    def setUp(self):
        from engine.crawler import Crawler
        self.logger = MagicMock()
        self.logger.log_crawler_event = MagicMock()
        self.logger.log_error = MagicMock()
        self.crawler = Crawler(config={
            "cpu_threshold": 70,
            "mem_threshold": 60,
            "suspicious_names": ["nc"],
            "temp_paths": ["/tmp"],
            "whitelist_root": ["systemd"],
            "trusted_ips": ["127.0.0.1"],
            "sensitive_ports": [22],
        }, logger=self.logger, interval=999)

    def test_fingerprint_is_deterministic(self):
        """Same inputs always produce same fingerprint."""
        fp1 = self.crawler._fingerprint(1234, "nc", "2026-01-01 00:00:00", "High CPU: 95%")
        fp2 = self.crawler._fingerprint(1234, "nc", "2026-01-01 00:00:00", "High CPU: 95%")
        self.assertEqual(fp1, fp2)

    def test_different_pid_different_fingerprint(self):
        fp1 = self.crawler._fingerprint(1234, "nc", "2026-01-01 00:00:00", "High CPU: 95%")
        fp2 = self.crawler._fingerprint(9999, "nc", "2026-01-01 00:00:00", "High CPU: 95%")
        self.assertNotEqual(fp1, fp2)

    def test_different_alert_different_fingerprint(self):
        fp1 = self.crawler._fingerprint(1234, "nc", "2026-01-01 00:00:00", "High CPU: 95%")
        fp2 = self.crawler._fingerprint(1234, "nc", "2026-01-01 00:00:00", "High Memory: 80%")
        self.assertNotEqual(fp1, fp2)

    def test_reused_pid_new_start_time_different_fingerprint(self):
        """If a PID is reused by a new process, it should NOT be treated as duplicate."""
        fp1 = self.crawler._fingerprint(1234, "nc", "2026-01-01 06:00:00", "High CPU: 95%")
        fp2 = self.crawler._fingerprint(1234, "nc", "2026-01-01 07:30:00", "High CPU: 95%")
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_is_16_chars(self):
        fp = self.crawler._fingerprint(1, "test", "2026-01-01", "alert")
        self.assertEqual(len(fp), 16)


class TestDeduplication(unittest.TestCase):
    """Test that the crawler correctly deduplicates alerts."""

    def setUp(self):
        from engine.crawler import Crawler
        self.logger = MagicMock()
        self.logger.log_crawler_event = MagicMock()
        self.logger.log_error = MagicMock()
        self.config = {
            "cpu_threshold": 70, "mem_threshold": 60,
            "suspicious_names": ["nc"], "temp_paths": ["/tmp"],
            "whitelist_root": ["systemd"], "trusted_ips": ["127.0.0.1"],
            "sensitive_ports": [22],
        }
        self.crawler = Crawler(config=self.config, logger=self.logger, interval=999)

    def _run_scan_with(self, evaluations):
        """Inject fake evaluations directly into _scan_once logic."""
        with patch("engine.crawler.collect_all_processes", return_value=[]), \
             patch("engine.crawler.scan_all", return_value=evaluations):
            self.crawler._scan_once()

    def test_first_alert_is_logged(self):
        ev = FakeEval(1234, "nc", "RISKY", 9, ["Suspicious keyword 'nc' in process"])
        self._run_scan_with([ev])
        self.assertEqual(self.crawler.new_alert_count, 1)
        self.assertEqual(self.crawler.duplicate_count, 0)

    def test_same_alert_second_scan_is_duplicate(self):
        ev = FakeEval(1234, "nc", "RISKY", 9, ["Suspicious keyword 'nc' in process"])
        self._run_scan_with([ev])
        self._run_scan_with([ev])   # second scan — same process still running
        self.assertEqual(self.crawler.new_alert_count, 1)
        self.assertEqual(self.crawler.duplicate_count, 1)

    def test_100_scans_same_process_logs_only_once(self):
        ev = FakeEval(1234, "nc", "RISKY", 9, ["Suspicious keyword 'nc' in process"])
        for _ in range(100):
            self._run_scan_with([ev])
        self.assertEqual(self.crawler.new_alert_count, 1)
        self.assertEqual(self.crawler.duplicate_count, 99)

    def test_different_alert_on_same_pid_logged_separately(self):
        ev1 = FakeEval(1234, "nc", "RISKY", 9, ["Suspicious keyword 'nc' in process"])
        ev2 = FakeEval(1234, "nc", "RISKY", 11, [
            "Suspicious keyword 'nc' in process",
            "Executable in temp directory: /tmp/nc"
        ])
        self._run_scan_with([ev1])
        self._run_scan_with([ev2])
        # First alert = duplicate, second alert = new
        self.assertEqual(self.crawler.new_alert_count, 2)
        self.assertEqual(self.crawler.duplicate_count, 1)

    def test_resolved_when_process_disappears(self):
        ev = FakeEval(1234, "nc", "RISKY", 9, ["Suspicious keyword 'nc' in process"])
        self._run_scan_with([ev])           # process appears
        self._run_scan_with([])             # process gone
        self.assertEqual(self.crawler.resolved_count, 1)
        self.assertNotIn(1234, self.crawler._active)

    def test_normal_process_not_tracked(self):
        ev = FakeEval(5678, "bash", "NORMAL", 0, [])
        self._run_scan_with([ev])
        self.assertEqual(self.crawler.new_alert_count, 0)
        self.assertEqual(self.crawler.duplicate_count, 0)


class TestCrawlerControls(unittest.TestCase):
    """Test start/stop/reset lifecycle."""

    def setUp(self):
        from engine.crawler import Crawler
        self.logger = MagicMock()
        self.logger.log_crawler_event = MagicMock()
        self.logger.log_error = MagicMock()
        self.crawler = Crawler(config={
            "cpu_threshold": 70, "mem_threshold": 60,
            "suspicious_names": [], "temp_paths": [],
            "whitelist_root": [], "trusted_ips": [],
            "sensitive_ports": [],
        }, logger=self.logger, interval=999)

    def test_not_running_before_start(self):
        self.assertFalse(self.crawler.is_running())

    def test_running_after_start(self):
        with patch("engine.crawler.collect_all_processes", return_value=[]), \
             patch("engine.crawler.scan_all", return_value=[]):
            self.crawler.start()
            time.sleep(0.1)
            self.assertTrue(self.crawler.is_running())
            self.crawler.stop()

    def test_not_running_after_stop(self):
        with patch("engine.crawler.collect_all_processes", return_value=[]), \
             patch("engine.crawler.scan_all", return_value=[]):
            self.crawler.start()
            time.sleep(0.1)
            self.crawler.stop()
            self.assertFalse(self.crawler.is_running())

    def test_reset_clears_state(self):
        with patch("engine.crawler.collect_all_processes", return_value=[]), \
             patch("engine.crawler.scan_all", return_value=[
                 FakeEval(1234, "nc", "RISKY", 9, ["alert"])
             ]):
            self.crawler._scan_once()
        self.assertEqual(self.crawler.new_alert_count, 1)
        self.crawler.reset()
        self.assertEqual(self.crawler.new_alert_count, 0)
        self.assertEqual(self.crawler.duplicate_count, 0)
        self.assertEqual(len(self.crawler._seen_fingerprints), 0)

    def test_get_summary_returns_dict(self):
        s = self.crawler.get_summary()
        self.assertIn("total_scans",     s)
        self.assertIn("new_alert_count", s)
        self.assertIn("duplicate_count", s)
        self.assertIn("resolved_count",  s)
        self.assertIn("active_flagged",  s)
        self.assertIn("recent_alerts",   s)


if __name__ == "__main__":
    unittest.main()
