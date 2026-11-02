"""Source-bound negative controls for the optional user timer status probe.

No host systemctl, D-Bus session, scheduling changes, or service writes occur.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from falsicore import monitor


class TimerStatusNegativeControls(unittest.TestCase):
    def probe(self, *, stdout: str, stderr: str = "", status: str = "COMPLETED") -> str:
        bus = {"XDG_RUNTIME_DIR": "/synthetic/run/user"}
        response = {"stdout": stdout, "stderr": stderr, "status": status}
        with patch.object(monitor, "user_bus_env", return_value=bus) as env, \
                patch.object(monitor, "run_command", return_value=response) as command:
            result = monitor.status()
        env.assert_called_once_with()
        command.assert_called_once_with(
            "systemctl", ["--user", "is-enabled", monitor.TIMER_NAME],
            timeout=12, limit=2048, env=bus,
        )
        return result

    def test_enabled_timer_has_explicit_state_and_bounded_query(self):
        self.assertEqual(self.probe(stdout="enabled\n"), "user systemd timer status: enabled")

    def test_disabled_timer_is_benign_even_when_is_enabled_exits_nonzero(self):
        self.assertEqual(self.probe(stdout="disabled\n", status="FAILED"),
                         "user systemd timer status: disabled")

    def test_empty_stdout_reports_only_first_failure_diagnostic(self):
        self.assertEqual(self.probe(stdout="", stderr="user manager unavailable\nprivate detail\n", status="FAILED"),
                         "user systemd timer status: UNKNOWN (FAILED: user manager unavailable)")

    def test_missing_binary_cannot_be_called_enabled(self):
        self.assertEqual(self.probe(stdout="", status="UNAVAILABLE"),
                         "user systemd timer status: UNKNOWN (UNAVAILABLE)")

    def test_failed_bus_preflight_never_starts_a_probe(self):
        with patch.object(monitor, "user_bus_env", side_effect=RuntimeError("no user session")), \
                patch.object(monitor, "run_command") as command:
            with self.assertRaisesRegex(RuntimeError, "no user session"):
                monitor.status()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
