import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from falsicore import detectors as d
from falsicore.collectors import Audit
from falsicore.report import (OUTCOME_UA, report_data, write_reports, verify_reports)

class ReportingTests(unittest.TestCase):
    def fake(self):
        return SimpleNamespace(
            scope="user", started_utc="2026-10-27T00:00:00+00:00",
            coverage=[{"check": x, "status": "COMPLETED", "details": "fixture"} for x in ("processes","network","persistence","browsers","auth","packages")],
            findings=[], dropped_findings=0,
            stats={"host": {"kernel": "fixture"}},
            baseline={"listeners": ["tcp/22"], "process_exe_hashes":[], "systemd_units":[], "cron_entry_hashes":[], "ssh_key_fingerprints":[],"browser_extensions":[],"native_hosts":[]},
            commands=[], private_index={}
        )

    def test_report_schema(self):
        self.assertEqual(report_data(self.fake())["schema"], "falsicore.summary.v4")

    def test_no_claim_of_compromise(self):
        self.assertFalse(report_data(self.fake())["confirmed_compromise"])

    def test_findings_trigger_review(self):
        f = self.fake()
        f.findings=[{"id": "F0001", "rule":"EXECUTABLE_IN_VOLATILE_PATH", "kind":"INDICATOR", "severity":"high", "source_ref":"src_123"}]
        self.assertEqual(report_data(f)["outcome"], "SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION")

    def test_write_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            write_reports(Path(td), self.fake())
            self.assertTrue(verify_reports(Path(td))["verified"])

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as td:
            dir = Path(td)
            write_reports(dir, self.fake())
            (dir / "report.md").write_text("tampered")
            self.assertFalse(verify_reports(dir)["verified"])

    def test_baseline_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old = root / "old"
            new = root / "new"
            old.mkdir(mode=0o700)
            new.mkdir(mode=0o700)
            write_reports(old, self.fake())
            second = self.fake()
            second.baseline["listeners"] = ["tcp/443"]
            write_reports(new, second, compare_report=old / "summary.json")
            delta = json.loads((new / "baseline_diff.json").read_text())
            self.assertIn("tcp/443", delta["listeners"]["added"])

    def test_bad_schema_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text('{"schema":"wrong","baseline":{}}')
            with self.assertRaises(ValueError):
                write_reports(Path(td), self.fake(), compare_report=path)

    def test_coverage_uncertainty_marked(self):
        f = self.fake()
        f.coverage[0]["status"] = "PARTIAL"
        self.assertEqual(report_data(f)["outcome"], "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")

    def test_private_index_is_separate(self):
        with tempfile.TemporaryDirectory() as td:
            write_reports(Path(td), self.fake())
            self.assertTrue((Path(td) / "private_index.json").exists())
            self.assertNotIn("source_ref_to_path", (Path(td) / "report.md").read_text())

    def test_auto_verdict_never_confirmed(self):
        f = self.fake()
        f.findings=[{"id":"F1","rule":"HIGH","kind":"INDICATOR","severity":"critical","source_ref":"id"}]
        self.assertNotIn("CONFIRMED", report_data(f)["outcome"])
