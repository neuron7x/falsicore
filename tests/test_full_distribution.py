"""ONE full distribution ZIP: deterministic, self-consistent, no self-referential hash."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from tools import build_full, build_release


class FullDistributionContracts(unittest.TestCase):
    def test_two_builds_are_identical_and_hash_is_outside(self):
        with tempfile.TemporaryDirectory() as td:
            a = build_full.build(Path(td) / "a")
            b = build_full.build(Path(td) / "b")
            self.assertEqual(a["zip_sha256"], b["zip_sha256"])
            sidecar = Path(a["zip"] + ".sha256").read_text()
            self.assertEqual(sidecar.split()[0], hashlib.sha256(Path(a["zip"]).read_bytes()).hexdigest())
            with ZipFile(a["zip"]) as z:
                names = z.namelist()
                prefix = names[0].split("/", 1)[0] + "/"
                self.assertTrue(all(n.startswith(prefix) for n in names))
                sums = z.read(prefix + "SHA256SUMS").decode()
                self.assertNotIn("SHA256SUMS", sums)
                self.assertNotIn(".zip", sums)
                for line in sums.splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256(z.read(prefix + name)).hexdigest(), digest, name)
                pyz = z.read(prefix + "falsicore.pyz")
                self.assertIn(hashlib.sha256(pyz).hexdigest(), z.read(prefix + "run.sh").decode())
                self.assertEqual(hashlib.sha256(pyz).hexdigest(), a["pyz_sha256"])
                self.assertIn(prefix + "source/SOURCE_MANIFEST.sha256", names)
                self.assertFalse(any(".falsicore-audit" in n or "private_index" in n for n in names))

    def test_stale_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(build_release, "manifest_for", return_value=b"stale\n"):
                with self.assertRaises(ValueError):
                    build_full.build(Path(td) / "out")

    def test_evidence_must_be_sanitized_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as td:
            ev = Path(td) / "ev"
            ev.mkdir()
            (ev / "ok.json").write_text('{"tests": 1}')
            self.assertIn("verification/ok.json", build_full._evidence(ev))
            (ev / "leak.md").write_text("report at /home/someone/run-1")
            with self.assertRaises(ValueError):
                build_full._evidence(ev)
            (ev / "leak.md").unlink()
            (ev / "binary.bin").write_bytes(b"\0")
            with self.assertRaises(ValueError):
                build_full._evidence(ev)

    def test_output_inside_source_tree_is_refused(self):
        with self.assertRaises(ValueError):
            build_full.build(build_release.ROOT / "dist-should-not-exist")


    def test_workflow_changes_do_not_invalidate_source_manifest(self):
        """R-10: automated workflow bumps must not break the tool's manifest."""
        manifest = build_release.current_manifest().decode()
        self.assertNotIn(".github/", manifest)
        self.assertTrue(build_release.automation_files())
        with tempfile.TemporaryDirectory() as td:
            result = build_full.build(Path(td) / "out")
            with ZipFile(result["zip"]) as z:
                prefix = z.namelist()[0].split("/", 1)[0] + "/"
                sums = z.read(prefix + "SHA256SUMS").decode()
                for wf in build_release.automation_files():
                    rel = "source/" + wf.relative_to(build_release.ROOT).as_posix()
                    self.assertIn(rel, sums)
                    self.assertEqual(z.read(prefix + rel), wf.read_bytes())


if __name__ == "__main__":
    unittest.main()
