"""Cross-boundary contracts for the initial public release."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import detectors, safety
from falsicore.cli import main
from falsicore.collectors import Audit
from falsicore.report import write_reports, verify_reports
from falsicore.cli import explain_report
from tools import build_release


class AtomicCollectorTests(unittest.TestCase):
    def _audit(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            return Audit(scope="user", target_user="nobody", profile="standard", max_seconds=8)

    def test_collector_exception_rolls_back_all_observations(self):
        audit = self._audit()
        names = list(audit.profile_config["checks"])
        def succeed(name):
            def run(self):
                self.checked(name, "COMPLETED", "synthetic success")
            return run
        def fail(self):
            self.finding("INJECTED_RULE", "high", "incomplete", "/tmp/partial")
            self.stats["partial"] = "must not survive"
            self.baseline["listeners"].append("must_not_survive")
            self.private_index["x"] = "must_not_survive"
            self.suspicious_exec_pids.add(123456)
            self.checked("persistence", "COMPLETED", "this is a lie")
            raise RuntimeError("synthetic failure")
        patches = [patch.object(Audit, name, fail if name == "persistence" else succeed(name))
                   for name in names]
        for item in patches:
            item.start()
        try:
            audit.scan()
        finally:
            for item in reversed(patches):
                item.stop()
        self.assertEqual(audit.findings, [])
        self.assertNotIn("partial", audit.stats)
        self.assertEqual(audit.baseline["listeners"], [])
        self.assertNotIn("x", audit.private_index)
        self.assertEqual(audit.suspicious_exec_pids, set())
        self.assertEqual(audit._next, 0)
        relevant = [x for x in audit.coverage if x["check"] == "persistence"]
        self.assertEqual(len(relevant), 1)
        self.assertEqual(relevant[0]["status"], "FAILED")

    def test_failed_collector_does_not_hide_successful_neighbor(self):
        audit = self._audit()
        def normal(name):
            def run(self):
                self.stats[name] = {"ok": True}
                self.checked(name, "COMPLETED", "ok")
            return run
        def failed(self):
            raise OSError("test")
        patches = [patch.object(Audit, name, failed if name == "auth" else normal(name))
                   for name in audit.profile_config["checks"]]
        for p in patches: p.start()
        try:
            audit.scan()
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual(len([x for x in audit.coverage if x["status"] == "FAILED"]), 1)
        self.assertEqual(audit.stats["environment"], {"ok": True})
        self.assertEqual(audit.stats["kernel"], {"ok": True})


class ReportIntegrityTests(unittest.TestCase):
    def _audit(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            return Audit(scope="user", target_user="nobody")

    def test_report_tampering_and_unknown_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "run"
            folder.mkdir(mode=0o700)
            audit = self._audit()
            audit.checked("auth", "PARTIAL", "synthetic fixture", reasons=["INPUT_TRUNCATED"])
            write_reports(folder, audit)
            self.assertTrue(verify_reports(folder)["verified"])
            (folder / "unexpected-private-file").write_text("private")
            self.assertFalse(verify_reports(folder)["verified"])
            (folder / "unexpected-private-file").unlink()
            (folder / "summary.json").write_text("{}")
            self.assertFalse(verify_reports(folder)["verified"])
            with self.assertRaises(ValueError):
                explain_report(folder)

    def test_report_refuses_symlink_entries(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "run"
            folder.mkdir(mode=0o700)
            audit = self._audit()
            write_reports(folder, audit)
            data = (folder / "findings.json").read_bytes()
            (folder / "findings.json").unlink()
            outside = Path(td) / "outside"
            outside.write_bytes(data)
            (folder / "findings.json").symlink_to(outside)
            self.assertFalse(verify_reports(folder)["verified"])


class ReleaseBoundaryTests(unittest.TestCase):
    def test_allowlist_rejects_generated_private_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            (root / "README.md").write_text("fixture")
            (root / "private_leak_test.json").write_text('{"personal": true}')
            with patch.object(build_release, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Unexpected release payload"):
                    build_release.source_files()

    def test_allowlist_rejects_symlink_directories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            (root / "README.md").write_text("fixture")
            (root / "generated-link-test").symlink_to(Path(td), target_is_directory=True)
            with patch.object(build_release, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Symlink source forbidden"):
                    build_release.source_files()

    def test_release_refuses_symlink_output(self):
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "archive.zip"
            dest = Path(td) / "target.dat"
            dest.write_bytes(b"not a zip")
            link.symlink_to(dest)
            with self.assertRaisesRegex(ValueError, "cannot be a symlink"):
                build_release.build(link)
            self.assertEqual(dest.read_bytes(), b"not a zip")

    def test_release_manifest_has_no_sensitive_local_artifacts(self):
        self.assertTrue(build_release.allowed_release_path(Path("falsicore/cli.py")))
        for path in ("private_index.json", "run-123/summary.json", "reports/private.json",
                     "logs.txt", ".env", "secret.key"):
            self.assertFalse(build_release.allowed_release_path(Path(path)), path)

    def test_executable_whitelist_fails_closed(self):
        with self.assertRaises(ValueError):
            safety.checked_executable("curl")
        with self.assertRaises(ValueError):
            safety.run_command("sh", ["-c", "echo hi"])

    def test_detector_only_handles_exact_webextension_domains(self):
        for pattern in ("https://fakeinstagram.com/*", "https://instagram.com.evil.test/*",
                        "https://www.instagram.com.evil.test/*", "http://notinstagram.com/*"):
            self.assertFalse(detectors.grants_instagram_access(pattern))
        for pattern in ("https://instagram.com/*", "*://*.instagram.com/*", "<all_urls>"):
            self.assertTrue(detectors.grants_instagram_access(pattern))


class CLISurfaceTests(unittest.TestCase):
    def test_doctor(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["doctor"]), 0)
        self.assertIn("NO automatic sudo", output.getvalue())

    def test_version(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(output):
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        from falsicore import __version__
        self.assertEqual(output.getvalue().strip(), __version__)


if __name__ == "__main__":
    unittest.main()
