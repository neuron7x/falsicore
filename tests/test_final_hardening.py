"""Regression suite for independently observed release blockers (2026-10-27)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import safety
from falsicore.collectors import Audit
from falsicore.report import verify_reports, write_reports


class ProcessCompletionContracts(unittest.TestCase):
    def _run(self, script: str, timeout: float = 0.3, limit: int = 4096) -> dict:
        with patch.object(safety, "checked_executable", return_value=sys.executable):
            return safety.run_command("uname", ["-c", script], timeout=timeout, limit=limit)

    def test_stdout_eof_before_parent_exit_is_not_success(self):
        result = self._run("import os,time;os.close(1);time.sleep(5)")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error"], "timeout")

    def test_child_normal_exit_after_stdout_is_success(self):
        result = self._run("import sys;sys.stdout.write('ok')", timeout=2)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["stdout"], "ok")
        self.assertEqual(result["exit"], 0)

    def test_child_nonzero_exit_is_not_success(self):
        result = self._run("import sys;sys.exit(17)", timeout=2)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["exit"], 17)

    def test_output_limit_does_not_overcollect(self):
        result = self._run("import sys;sys.stdout.write('x'*4096)", timeout=2, limit=31)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["error"], "output limit exceeded")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), 31)

    def test_argument_nul_rejected_without_process(self):
        with patch.object(safety, "checked_executable", return_value=sys.executable):
            with self.assertRaises(ValueError):
                safety.run_command("uname", ["abc\0def"])


class SemanticEvidenceContracts(unittest.TestCase):
    def test_consistent_reports_pass_and_rehashed_forgery_fails(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "run"
            folder.mkdir(mode=0o700)
            with patch("falsicore.collectors.os.geteuid", return_value=1001), \
                 patch("falsicore.collectors.os.getuid", return_value=1001):
                audit = Audit(scope="user", target_user="nobody")
            audit.checked("auth", "PARTIAL", "test fixture")
            write_reports(folder, audit)
            self.assertTrue(verify_reports(folder)["verified"])
            s = json.loads((folder / "summary.json").read_text())
            s["outcome"] = "NO_COMPROMISE_INDICATORS_OBSERVED"
            (folder / "summary.json").write_text(json.dumps(s))
            # A manifest hash can be recomputed; report must additionally
            # detect semantic disagreement. This is NOT a digital signature.
            lines = []
            for name in sorted(p.name for p in folder.iterdir() if p.name != "evidence_manifest.sha256"):
                lines.append(hashlib.sha256((folder / name).read_bytes()).hexdigest() + "  " + name)
            (folder / "evidence_manifest.sha256").write_text("\n".join(lines) + "\n")
            report = verify_reports(folder)
            self.assertTrue(report["complete_file_set"])
            self.assertTrue(all(entry["verified"] for entry in report["entries"]))
            self.assertFalse(report["semantic_consistency"])
            self.assertFalse(report["verified"])

    def test_forged_report_with_malformed_content_fails(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "run"
            folder.mkdir(mode=0o700)
            with patch("falsicore.collectors.os.geteuid", return_value=1001), \
                 patch("falsicore.collectors.os.getuid", return_value=1001):
                audit = Audit(scope="user", target_user="nobody")
            write_reports(folder, audit)
            path = folder / "coverage_matrix.json"
            path.write_text("{not json}")
            contents = []
            for candidate in sorted(folder.iterdir()):
                if candidate.name != "evidence_manifest.sha256":
                    contents.append(hashlib.sha256(candidate.read_bytes()).hexdigest()+"  "+candidate.name)
            (folder / "evidence_manifest.sha256").write_text("\n".join(contents)+"\n")
            self.assertFalse(verify_reports(folder)["verified"])


class MissingTelemetryIsNotNegative(unittest.TestCase):
    def _audit(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            return Audit(scope="user", target_user="nobody")

    def test_missing_firefox_extension_metadata_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "abc.default-release").mkdir()
            audit = self._audit()
            n, incomplete = audit._scan_firefox(base)
            self.assertEqual(n, 0)
            self.assertTrue(incomplete)

    def test_missing_chromium_manifest_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "Default/Extensions/exampleextensionid/1.0.0").mkdir(parents=True)
            audit = self._audit()
            n, p, incomplete = audit._scan_chromium("chromium", base)
            self.assertEqual((n,p), (0,1))
            self.assertTrue(incomplete)

    def test_recursive_walk_error_sets_partial(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            audit = self._audit()
            def fake_walk(path, **kwargs):
                kwargs["onerror"](PermissionError("blocked subtree"))
                return iter([])
            with patch("falsicore.collectors.os.walk", side_effect=fake_walk):
                files, incomplete = audit._files([base], recursive=True)
            self.assertEqual(files, [])
            self.assertTrue(incomplete)


if __name__ == "__main__":
    unittest.main()
