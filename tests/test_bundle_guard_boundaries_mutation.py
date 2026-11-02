"""Falsify ZIP control-byte sanitization and export-parent permissions.

Source-derived targets: bundle:46:2-4 (control threshold) and
bundle:79:4 (0o022 permission mask). Only disposable synthetic ZIPs and
private temporary export roots are used; no scan or host write.
"""
from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from falsicore import bundle


class BundleMemberNameBoundaries(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.archive = Path(tmp.name) / "benign.pyz"

    def _write(self, name: str) -> bytes:
        data = b"safe synthetic data"
        manifest = {
            "schema": "falsicore.bundle.v1",
            "sha256": {name: hashlib.sha256(data).hexdigest()},
        }
        with ZipFile(self.archive, "w") as archive:
            archive.writestr(name, data)
            archive.writestr(bundle.MANIFEST, json.dumps(manifest, sort_keys=True))
        return data

    def test_tab_in_member_name_is_rejected(self):
        self._write("tab\tmember.txt")
        with self.assertRaisesRegex(ValueError, "Unsafe bundle member"):
            bundle.read_verified_bundle(self.archive)

    def test_unit_separator_in_member_name_is_rejected(self):
        self._write("control\x1fmember.txt")
        with self.assertRaisesRegex(ValueError, "Unsafe bundle member"):
            bundle.read_verified_bundle(self.archive)

    def test_benign_space_in_member_name_is_accepted(self):
        name = "benign space.txt"
        data = self._write(name)
        self.assertEqual(bundle.read_verified_bundle(self.archive), {name: data})

    def test_benign_printable_exclamation_is_accepted(self):
        name = "benign!member.txt"
        data = self._write(name)
        self.assertEqual(bundle.read_verified_bundle(self.archive), {name: data})


class BundleExportParentPermissions(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name) / "candidate"
        self.parent.mkdir()
        self.destination = self.parent / "export"

    def test_owned_0755_nonwritable_parent_is_accepted(self):
        self.parent.chmod(0o755)
        exported = bundle.export_source({"README.txt": b"benign"}, self.destination)
        self.assertEqual(exported, self.destination)
        self.assertEqual((exported / "README.txt").read_bytes(), b"benign")
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o700)

    def test_group_writable_parent_is_rejected_without_export(self):
        self.parent.chmod(0o775)
        with self.assertRaisesRegex(PermissionError, "Export parent"):
            bundle.export_source({"README.txt": b"data"}, self.destination)
        self.assertFalse(self.destination.exists())

    def test_world_writable_parent_is_rejected_without_export(self):
        self.parent.chmod(0o757)
        with self.assertRaisesRegex(PermissionError, "Export parent"):
            bundle.export_source({"README.txt": b"data"}, self.destination)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
