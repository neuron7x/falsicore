"""Release-stage negative scenarios: integrity, scheduling, command bounds."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import monitor, report, safety
from tools import build_release


class ReportValidationTests(unittest.TestCase):
    def test_invalid_manifest_line_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "evidence_manifest.sha256").write_text("garbage\n", encoding="utf8")
            result = report.verify_reports(p)
            self.assertFalse(result["verified"])
            self.assertEqual(result["entries"][0]["entry"], "INVALID_MANIFEST_LINE")

    def test_duplicate_manifest_entry_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "summary.json").write_text("{}")
            line = "0" * 64 + "  summary.json\n"
            (p / "evidence_manifest.sha256").write_text(line * 2)
            result = report.verify_reports(p)
            self.assertFalse(result["verified"])
            self.assertIn("INVALID_OR_DUPLICATE_ENTRY", [x["entry"] for x in result["entries"]])

    def test_baseline_path_requires_summary_name(self):
        with self.assertRaises(ValueError):
            report.load_verified_summary(Path("/tmp/fake-other.json"))

    def test_baseline_fails_missing_and_invalid_json(self):
        with patch.object(report, "verify_reports", return_value={"verified": False}):
            with self.assertRaises(ValueError):
                report.load_verified_summary(Path("/tmp/summary.json"))
        with patch.object(report, "verify_reports", return_value={"verified": True}), \
             patch.object(report, "safe_read", return_value=(None, "ABSENT")):
            with self.assertRaises(ValueError):
                report.load_verified_summary(Path("/tmp/summary.json"))
        with patch.object(report, "verify_reports", return_value={"verified": True}), \
             patch.object(report, "safe_read", return_value=(b"{not json}", "COMPLETED")):
            with self.assertRaises(ValueError):
                report.load_verified_summary(Path("/tmp/summary.json"))

    def test_baseline_refuses_bad_structured_payload(self):
        with patch.object(report, "verify_reports", return_value={"verified": True}), \
             patch.object(report, "safe_read", return_value=(b'[]', "COMPLETED")):
            with self.assertRaises(ValueError):
                report.load_verified_summary(Path("/tmp/summary.json"))

    def test_find_baseline_missing_parent_and_incompatible(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            self.assertIsNone(report.find_baseline(p / "absent", {"schema": report.SCHEMA}))
            run = p / "run-one"
            run.mkdir(mode=0o700)
            with patch.object(report, "load_verified_summary", return_value={"schema": "other"}):
                self.assertIsNone(report.find_baseline(p, {"schema": report.SCHEMA}))
            with patch.object(report, "load_verified_summary", return_value={"schema": report.SCHEMA}):
                self.assertEqual(report.find_baseline(p, {"schema": report.SCHEMA}), run / "summary.json")

    def test_find_baseline_skips_corrupt_report(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "run-one").mkdir(mode=0o700)
            with patch.object(report, "load_verified_summary", side_effect=ValueError("bad")):
                self.assertIsNone(report.find_baseline(p, {"schema": report.SCHEMA}))

    def test_digest_and_finding_identity_ignores_input_order(self):
        findings = [
            {"rule":"A", "severity":"medium", "kind":"EXPOSURE", "source_ref":"one", "evidence": {}},
            {"rule":"B", "severity":"high", "kind":"INDICATOR", "source_ref":"two", "evidence": {}},
        ]
        coverage = [{"check":"network","status":"PARTIAL","details":"gap"}]
        self.assertEqual(report._analysis_digest(findings, coverage), report._analysis_digest(list(reversed(findings)), coverage))
        self.assertEqual(report.stable_findings(findings)[0]["rule"], "B")


class SchedulingIsolationTests(unittest.TestCase):
    def setUp(self):
        # Unit tests must not depend on a login session existing on the test
        # host (CI runners have no /run/user/<uid>); the env itself is tested
        # in test_monitor_env.py.
        patcher = patch.object(monitor, "user_bus_env", return_value=monitor.minimal_env())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unit_content_and_invalid_unit_path(self):
        root = Path(__file__).resolve().parents[1]
        service, timer = monitor.unit_contents(root)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("Persistent=true", timer)
        with self.assertRaises(ValueError):
            monitor._escape_systemd_argument("bad\nname")
        with self.assertRaises(ValueError):
            monitor._escape_systemd_argument("bad%name")

    def test_enable_disable_are_explicit_and_non_destructive(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            bundle = Path(__file__).resolve().parents[1]
            completed = {"status": "COMPLETED", "stdout": "", "exit": 0}
            with patch.object(monitor.os, "geteuid", return_value=1000), \
                 patch.object(monitor, "run_command", return_value=completed) as cmd:
                self.assertIn("ENABLED", monitor.enable(bundle, home))
                self.assertTrue((home / ".config/systemd/user" / monitor.TIMER_NAME).exists())
                self.assertIn("DISABLED", monitor.disable(bundle, home))
                self.assertFalse((home / ".config/systemd/user" / monitor.SERVICE_NAME).exists())
                self.assertGreaterEqual(cmd.call_count, 4)

    def test_enable_refuses_modified_unit(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            folder = home / ".config/systemd/user"
            folder.mkdir(parents=True)
            (folder / monitor.SERVICE_NAME).write_text("malicious owner-changed file")
            with patch.object(monitor.os, "geteuid", return_value=1000):
                with self.assertRaises(FileExistsError):
                    monitor.enable(Path(__file__).resolve().parents[1], home)
            self.assertEqual((folder / monitor.SERVICE_NAME).read_text(), "malicious owner-changed file")

    def test_enable_refuses_root_and_systemctl_failure(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(monitor.os, "geteuid", return_value=0):
                with self.assertRaises(PermissionError):
                    monitor.enable(Path(__file__).resolve().parents[1], Path(td))
            with patch.object(monitor.os, "geteuid", return_value=1000), \
                 patch.object(monitor, "run_command", return_value={"status":"UNAVAILABLE"}):
                with self.assertRaises(RuntimeError):
                    monitor.enable(Path(__file__).resolve().parents[1], Path(td))

    def test_disable_refuses_changed_unit(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / ".config/systemd/user"
            folder.mkdir(parents=True)
            (folder / monitor.TIMER_NAME).write_text("changed")
            with patch.object(monitor.os, "geteuid", return_value=1000):
                with self.assertRaises(PermissionError):
                    monitor.disable(Path(__file__).resolve().parents[1], Path(td))


class IOInvariantTests(unittest.TestCase):
    def test_reject_null_and_wrong_command_arguments(self):
        with self.assertRaises(ValueError):
            safety.run_command("uname", [3])
        with self.assertRaises(ValueError):
            safety.run_command("uname", ["-a"], limit=safety.MAX_COMMAND_OUTPUT + 1)
        with patch.object(safety, "checked_executable", return_value=None):
            self.assertEqual(safety.run_command("uname", ["-a"])["status"], "UNAVAILABLE")

    def test_safe_read_rejects_directory_and_invalid_bound(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(safety.safe_read(Path(td))[1], "NOT_REGULAR")
            self.assertEqual(safety.safe_read(Path("/"))[1], "INVALID_PATH")
            with self.assertRaises(ValueError):
                safety.safe_read(Path(td), -1)

    def test_release_destination_inside_repo_refused(self):
        with self.assertRaisesRegex(ValueError, "outside the source tree"):
            build_release.build(build_release.ROOT / "should-not-exist.zip")


if __name__ == "__main__":
    unittest.main()
