"""
tests/test_services.py
Unit tests for the service collector and related logic.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import unittest
from Collectors.service_collector import ServiceInfo


class TestServiceInfo(unittest.TestCase):
    def _make(self, active="active", sub="running", load="loaded"):
        return ServiceInfo(
            name="test.service",
            active_state=active,
            sub_state=sub,
            load_state=load,
        )

    def test_running_service(self):
        svc = self._make(active="active", sub="running")
        self.assertTrue(svc.is_running)
        self.assertEqual(svc.status_label, "RUNNING")

    def test_failed_service(self):
        svc = self._make(active="failed", sub="failed")
        self.assertFalse(svc.is_running)
        self.assertEqual(svc.status_label, "FAILED")

    def test_inactive_service(self):
        svc = self._make(active="inactive", sub="dead")
        self.assertFalse(svc.is_running)
        self.assertEqual(svc.status_label, "STOPPED")

    def test_activating_service(self):
        svc = self._make(active="activating", sub="start")
        self.assertFalse(svc.is_running)
        self.assertEqual(svc.status_label, "ACTIVATING")

    def test_service_name_stored(self):
        svc = ServiceInfo(name="sshd.service")
        self.assertEqual(svc.name, "sshd.service")

    def test_default_pid_zero(self):
        svc = ServiceInfo(name="x.service")
        self.assertEqual(svc.pid, 0)


class TestCollectServicesImport(unittest.TestCase):
    """Smoke test: collect_services should return a list (possibly empty)."""

    def test_returns_list(self):
        from Collectors.service_collector import collect_services
        result = collect_services()
        self.assertIsInstance(result, list)

    def test_filter_applied(self):
        from Collectors.service_collector import collect_services
        # Using a filter that won't match anything real
        result = collect_services(unit_filter="XYZZY_NO_MATCH_9999")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
