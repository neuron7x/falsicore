"""CLI contracts: every public action succeeds or fails without assuming a clean host."""
from __future__ import annotations

import contextlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import cli


class EndUserInterfaceTests(unittest.TestCase):
    def capture(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = cli.main(args)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_main_module_dispatch(self):
        with patch("falsicore.cli.main", return_value=0) as entry:
            with self.assertRaises(SystemExit) as exit_info:
                runpy.run_module("falsicore.__main__", run_name="__main__")
        self.assertEqual(exit_info.exception.code, 0)
        entry.assert_called_once()

    def test_monitor_plan_and_status(self):
        code, out, err = self.capture(["monitor", "plan"])
        self.assertEqual(code, 0)
        self.assertIn("NoNewPrivileges=true", out)
        self.assertFalse(err)
        with patch.object(cli.monitor, "status", return_value="INACTIVE"):
            code, out, _ = self.capture(["monitor", "status"])
        self.assertEqual(code, 0)
        self.assertIn("INACTIVE", out)

    def test_monitor_enable_disable_and_failure(self):
        with patch.object(cli.monitor, "enable", return_value="enabled") as enable:
            code, out, _ = self.capture(["monitor", "enable"])
        self.assertEqual((code, out.strip()), (0, "enabled"))
        enable.assert_called_once()
        with patch.object(cli.monitor, "disable", return_value="disabled"):
            code, out, _ = self.capture(["monitor", "disable"])
        self.assertEqual((code, out.strip()), (0, "disabled"))
        with patch.object(cli.monitor, "unit_contents", side_effect=PermissionError("blocked")):
            code, _, err = self.capture(["monitor", "plan"])
        self.assertEqual(code, 2)
        self.assertIn("MONITOR ERROR", err)

    def test_explain_guard_failed_integrity(self):
        with patch.object(cli, "verify_reports", return_value={"verified": False}):
            code, _, err = self.capture(["explain", "/tmp/fixture"])
        self.assertEqual(code, 2)
        self.assertIn("integrity", err)

    def test_explain_missing_summary_and_schema(self):
        with patch.object(cli, "verify_reports", return_value={"verified": True}), \
             patch.object(cli, "safe_read", return_value=(None, "ABSENT")):
            code, _, err = self.capture(["explain", "/tmp/fixture"])
        self.assertEqual(code, 2)
        self.assertIn("Summary unavailable", err)
        with patch.object(cli, "verify_reports", return_value={"verified": True}), \
             patch.object(cli, "safe_read", return_value=(b'{}', "COMPLETED")):
            code, _, err = self.capture(["explain", "/tmp/fixture"])
        self.assertEqual(code, 2)
        self.assertIn("Unsupported report schema", err)

    def test_explain_success_interpretable_and_capped_gaps(self):
        sample = {"schema": "falsicore.summary.v3", "outcome": "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS",
                  "outcome_explanation_ua": "coverage gap", "profile": "quick", "scope": "user",
                  "finding_counts_by_kind": {"INDICATOR": 1, "EXPOSURE": 2},
                  "material_coverage_gaps": [{"check": "auth", "status": "PARTIAL", "reason": "no journal"}] * 15,
                  "analysis_digest_sha256": "a" * 64}
        with patch.object(cli, "verify_reports", return_value={"verified": True}), \
             patch.object(cli, "safe_read", return_value=(json.dumps(sample).encode(), "COMPLETED")):
            code, out, err = self.capture(["explain", "/tmp/fixture"])
        self.assertEqual(code, 0)
        self.assertFalse(err)
        self.assertIn("Кількість індикаторів (НЕ доказів): 1", out)
        self.assertEqual(out.count("no journal"), 12)

    def test_verify_returns_error_for_corrupted_and_good(self):
        response = {"verified": False, "entries": [{"verified": False, "entry": "summary.json"}]}
        with patch.object(cli, "verify_reports", return_value=response):
            code, out, _ = self.capture(["verify", "/tmp/fixture"])
        self.assertEqual(code, 2)
        self.assertIn("INVALID", out)
        self.assertIn("FAIL summary.json", out)
        response["verified"] = True
        response["entries"][0]["verified"] = True
        with patch.object(cli, "verify_reports", return_value=response):
            code, out, _ = self.capture(["verify", "/tmp/fixture"])
        self.assertEqual(code, 0)
        self.assertIn("PASS summary.json", out)

    def _scan_mock(self, verdict="INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS", verified=True):
        audit = SimpleNamespace(home=Path("/tmp"))
        audit.scan = lambda: None
        summary = {"outcome": verdict, "outcome_explanation_ua": "synthetic conclusion",
                   "finding_counts_by_kind": {"INDICATOR": 0}, "material_coverage_gaps": [],
                   "stats": {"runtime": {"elapsed_ms": 1}},
                   "baseline_comparison": {"status": "NO_COMPATIBLE_VERIFIED_BASELINE"}}
        p1 = patch.object(cli, "Audit", return_value=audit)
        p2 = patch.object(cli, "create_run_directory", return_value=Path("/tmp/run-fixture"))
        p3 = patch.object(cli, "write_reports", return_value=summary)
        p4 = patch.object(cli, "verify_reports", return_value={"verified": verified})
        return (p1, p2, p3, p4), audit, summary

    def test_scan_success_strict_exit_variants(self):
        cases = [("INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS", 11),
                 ("SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION", 10),
                 ("NO_COMPROMISE_INDICATORS_OBSERVED", 0)]
        for verdict, expected in cases:
            with self.subTest(verdict=verdict):
                patches, _, _ = self._scan_mock(verdict)
                for p in patches: p.start()
                try:
                    code, out, err = self.capture(["scan", "--strict-exit", "--profile", "quick"])
                    self.assertEqual(code, expected)
                    self.assertIn("VERIFIED PRIVATE REPORT:", out)
                    self.assertFalse(err)
                finally:
                    for p in reversed(patches): p.stop()

    def test_scan_incomplete_report_refused(self):
        patches, _, _ = self._scan_mock(verified=False)
        for p in patches: p.start()
        try:
            code, _, err = self.capture(["scan"])
            self.assertEqual(code, 2)
            self.assertIn("INCOMPLETE PRIVATE RUN", err)
        finally:
            for p in reversed(patches): p.stop()

    def test_scan_creation_failure_refused(self):
        with patch.object(cli, "Audit", side_effect=PermissionError("test error")):
            code, out, err = self.capture(["scan"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("SCAN ERROR", err)

    def test_scan_rejects_different_user(self):
        with patch.object(cli.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="safe")):
            code, _, err = self.capture(["scan", "--target-user", "different"])
        self.assertEqual(code, 2)
        self.assertIn("Unprivileged scan cannot select another user", err)

    def test_standard_scan_cli_success_not_strict(self):
        patches, _, _ = self._scan_mock()
        for p in patches: p.start()
        try:
            code, out, _ = self.capture(["scan", "--output-base", "/tmp/controlled-output"])
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual(code, 0)
        self.assertIn("INCONCLUSIVE", out)


if __name__ == "__main__":
    unittest.main()
