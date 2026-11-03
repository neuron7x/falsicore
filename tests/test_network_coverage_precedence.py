"""Prevent stale ss coverage from authorizing absence-based debugger conclusions.

Synthetic coverage/finding rows only; no host commands or network probes.
"""
import unittest

from falsicore.collectors import Audit


class LatestNetworkCoverageTests(unittest.TestCase):
    @staticmethod
    def correlate(first, latest, listeners=None):
        audit = Audit.__new__(Audit)
        audit.coverage = [
            {"check": "network", "status": first},
            {"check": "network", "status": latest},
        ]
        audit.listening_ports = listeners or {}
        audit.findings = [{
            "rule": "UNSAFE_BROWSER_LAUNCH_FLAG",
            "evidence": {"debug_port": "9222", "debug_port_listener": "NOT_CORRELATED"},
        }]
        audit._correlate_debug_ports()
        return audit.findings[0]["evidence"]["debug_port_listener"]

    def test_later_partial_invalidates_earlier_complete_absence(self):
        self.assertEqual(self.correlate("COMPLETED", "PARTIAL"), "UNKNOWN")

    def test_later_complete_can_authorize_absence_after_partial(self):
        self.assertEqual(self.correlate("PARTIAL", "COMPLETED"), "NOT_OBSERVED")

    def test_later_failure_invalidates_earlier_complete_absence(self):
        self.assertEqual(self.correlate("COMPLETED", "FAILED"), "UNKNOWN")

    def test_later_partial_retains_observed_wildcard_listener(self):
        self.assertEqual(
            self.correlate("COMPLETED", "PARTIAL", {"9222": {"wildcard"}}),
            "LISTENING_BEYOND_LOOPBACK",
        )

    def test_latest_complete_retains_benign_loopback_listener(self):
        self.assertEqual(
            self.correlate("COMPLETED", "COMPLETED", {"9222": {"loopback"}}),
            "LISTENING_LOOPBACK_ONLY",
        )


if __name__ == "__main__":
    unittest.main()
