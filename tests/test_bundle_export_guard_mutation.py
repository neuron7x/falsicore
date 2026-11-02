"""Direct export_source root-containment falsifiers and benign controls.

The whole-package bundle:86:2:boolop:swap mutant changes the absolute-or-
parent traversal rejection into an AND, permitting an out-of-root write.
These tests exercise export_source itself, not only ZIP member validation.
"""
from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from falsicore import bundle


class ExportSourceRootContainment(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "source"

    def test_absolute_member_rejected_without_outside_write(self):
        escaped = self.root / "absolute-escape.txt"
        with self.assertRaisesRegex(ValueError, "Unsafe source member"):
            bundle.export_source({str(escaped): b"untrusted"}, self.destination)
        self.assertFalse(escaped.exists())

    def test_parent_traversal_rejected_without_outside_write(self):
        escaped = self.root / "relative-escape.txt"
        with self.assertRaisesRegex(ValueError, "Unsafe source member"):
            bundle.export_source({"../relative-escape.txt": b"untrusted"}, self.destination)
        self.assertFalse(escaped.exists())

    def test_nested_parent_traversal_rejected(self):
        escaped = self.root / "nested-escape.txt"
        with self.assertRaisesRegex(ValueError, "Unsafe source member"):
            bundle.export_source({"sub/../../nested-escape.txt": b"untrusted"}, self.destination)
        self.assertFalse(escaped.exists())

    def test_benign_nested_relative_member_is_exported(self):
        exported = bundle.export_source({"docs/2026/report.txt": b"benign"}, self.destination)
        self.assertEqual(exported, self.destination)
        self.assertEqual((exported / "docs" / "2026" / "report.txt").read_bytes(), b"benign")
        self.assertFalse((self.root / "report.txt").exists())
        self.assertEqual(stat.S_IMODE((exported / "docs" / "2026").stat().st_mode), 0o700)

    def test_only_zipapp_entry_point_still_creates_private_destination(self):
        exported = bundle.export_source({"__main__.py": b"skip"}, self.destination)
        self.assertTrue(exported.is_dir())
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o700)
        self.assertEqual(list(exported.iterdir()), [])

    def test_zipapp_entry_point_is_skipped_but_regular_member_exported(self):
        exported = bundle.export_source(
            {"__main__.py": b"do not export", "README.md": b"benign"}, self.destination
        )
        self.assertFalse((exported / "__main__.py").exists())
        self.assertEqual((exported / "README.md").read_bytes(), b"benign")


if __name__ == "__main__":
    unittest.main()
