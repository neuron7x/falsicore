"""Operator progress: stderr only, phase transitions, heartbeat during long phases."""
from __future__ import annotations

import io
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import cli
from falsicore.collectors import Audit


class ProgressReporterTests(unittest.TestCase):
    def test_heartbeat_reports_running_phase(self):
        audit = SimpleNamespace(current_phase="packages")
        stream = io.StringIO()
        with cli.Progress(audit, interval=0.02, stream=stream):
            time.sleep(0.15)
        lines = stream.getvalue().splitlines()
        self.assertTrue(any("packages: still running" in x for x in lines), lines)

    def test_heartbeat_silent_without_phase(self):
        stream = io.StringIO()
        with cli.Progress(SimpleNamespace(current_phase=None), interval=0.02, stream=stream):
            time.sleep(0.08)
        self.assertEqual(stream.getvalue(), "")

    def test_heartbeat_stops_on_exit(self):
        audit = SimpleNamespace(current_phase="kernel")
        stream = io.StringIO()
        with cli.Progress(audit, interval=0.02, stream=stream):
            time.sleep(0.05)
        frozen = stream.getvalue()
        time.sleep(0.08)
        self.assertEqual(stream.getvalue(), frozen)

    def test_lines_are_timestamped_without_percentages(self):
        stream = io.StringIO()
        cli.Progress(None, interval=0, stream=stream)("network: start")
        line = stream.getvalue().strip()
        self.assertRegex(line, r"^\[\s*\d+\.\ds\] network: start$")
        self.assertNotIn("%", line)


class ScanProgressTests(unittest.TestCase):
    def _audit(self) -> Audit:
        audit = Audit.__new__(Audit)
        Audit.__init__(audit, scope="user", profile="quick")
        return audit

    def test_scan_emits_start_and_result_for_each_selected_collector(self):
        audit = self._audit()
        lines: list[str] = []
        names = audit.profile_config["checks"]
        with patch.multiple(Audit, **{n: lambda self, n=n: self.checked(n, "COMPLETED", "fixture") for n in names}):
            audit.scan(progress=lines.append)
        for i, name in enumerate(names, 1):
            self.assertIn(f"[{i}/{len(names)}] {name}: start", lines)
            self.assertTrue(any(x.startswith(f"{name}: COMPLETED (") for x in lines), lines)
        self.assertIsNone(audit.current_phase)

    def test_failed_collector_is_reported_as_failed(self):
        audit = self._audit()
        lines: list[str] = []

        def boom(self):
            raise OSError("fixture")
        others = {n: (lambda self, n=n: self.checked(n, "COMPLETED", "fixture"))
                  for n in audit.profile_config["checks"] if n != "network"}
        with patch.multiple(Audit, network=boom, **others):
            audit.scan(progress=lines.append)
        self.assertTrue(any(x.startswith("network: FAILED (") for x in lines), lines)
        self.assertTrue(any(x.startswith("persistence: COMPLETED (") for x in lines), lines)

    def test_progress_does_not_change_results(self):
        a, b = self._audit(), self._audit()
        names = a.profile_config["checks"]
        fake = {n: (lambda self, n=n: self.checked(n, "COMPLETED", "fixture")) for n in names}
        with patch.multiple(Audit, **fake):
            a.scan()
            b.scan(progress=lambda _line: None)
        self.assertEqual(a.coverage, b.coverage)
        self.assertEqual(a.findings, b.findings)


class ProgressFailureIsolationTests(unittest.TestCase):
    def test_none_stream_never_falls_back_to_stdout(self):
        out = io.StringIO()
        with patch("sys.stderr", None), patch("sys.stdout", out):
            cli.Progress(None, interval=0)("phase")
        self.assertEqual(out.getvalue(), "")

    def test_broken_stream_disables_progress_without_raising(self):
        class Broken(io.StringIO):
            def write(self, _s):
                raise BrokenPipeError
        progress = cli.Progress(None, interval=0, stream=Broken())
        progress("a")
        progress("b")
        self.assertFalse(progress.enabled)

    def test_failing_progress_callback_does_not_abort_scan(self):
        audit = Audit.__new__(Audit)
        Audit.__init__(audit, scope="user", profile="quick")
        names = audit.profile_config["checks"]

        def explode(_line):
            raise BrokenPipeError
        with patch.multiple(Audit, **{n: (lambda self, n=n: self.checked(n, "COMPLETED", "fixture")) for n in names}):
            audit.scan(progress=explode)
        self.assertEqual([c["check"] for c in audit.coverage if c["status"] == "COMPLETED"], list(names))

    def test_keyboard_interrupt_returns_130_with_run_path(self):
        fake = SimpleNamespace(scope="user", target_user="fixture", home=None, profile_config={"checks": ()},
                               max_seconds=5)

        def interrupted(**_kw):
            raise KeyboardInterrupt
        fake.scan = interrupted
        err = io.StringIO()
        with patch.object(cli, "Audit", return_value=fake), \
             patch.object(cli, "create_run_directory", return_value="/tmp/run-cancel-fixture"), \
             patch("sys.stderr", err):
            code = cli.main(["scan", "--profile", "quick", "--output-base", "/tmp/unused"])
        self.assertEqual(code, 130)
        self.assertIn("SCAN CANCELLED", err.getvalue())
        self.assertIn("/tmp/run-cancel-fixture", err.getvalue())


if __name__ == "__main__":
    unittest.main()
