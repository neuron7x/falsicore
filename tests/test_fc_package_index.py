"""Negative controls: dpkg/pacman reference-set truncation cannot yield COMPLETED."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import collectors
from falsicore.collectors import Audit


class PackageIndexCompleteness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = Audit.__new__(Audit)
        self.a.root, self.a.stats = self.root, {}
        self.a._dpkg_index, self.a._pacman_index = None, None
        self.a._package_db_gaps = {}

    def test_oversized_dpkg_record_is_explicitly_incomplete(self):
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (info / "one.md5sums").write_bytes(b"a" * (4 * 1024 * 1024 + 1))
        (self.root / "var/lib/dpkg/status").write_text("")
        self.assertIsNone(self.a._dpkg_md5(self.root / "bin/sh"))
        self.assertEqual(self.a._package_db_gaps["dpkg"]["INPUT_TRUNCATED"], 1)

    def test_dpkg_enumeration_cap_reports_excluded_records(self):
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (info / "a.md5sums").write_text("a" * 32 + "  bin/a\n")
        (info / "b.md5sums").write_text("b" * 32 + "  bin/b\n")
        (self.root / "var/lib/dpkg/status").write_text("")
        with patch.object(collectors, "DPKG_DB_MAX_RECORDS", 1):
            self.a._dpkg_md5(self.root / "bin/a")
        self.assertEqual(self.a._package_db_gaps["dpkg"]["ENUMERATION_LIMIT"], 1)

    def test_corrupt_pacman_mtree_marks_reference_set_incomplete(self):
        folder = self.root / "var/lib/pacman/local/pkg-1"
        folder.mkdir(parents=True)
        (folder / "mtree").write_text("not gzip")
        self.assertEqual(self.a._pacman_records(), {})
        self.assertEqual(self.a._package_db_gaps["pacman"]["PARSE_UNSUPPORTED"], 1)

    def test_pacman_record_cap_reports_excluded_metadata(self):
        folders = self.root / "var/lib/pacman/local"
        (folders / "pkg-a").mkdir(parents=True)
        (folders / "pkg-b").mkdir()
        with patch.object(collectors, "PACKAGE_DB_MAX_RECORDS", 1):
            self.a._pacman_records()
        self.assertEqual(self.a._package_db_gaps["pacman"]["ENUMERATION_LIMIT"], 1)

    def test_deep_packages_coverage_is_partial_on_reference_gap(self):
        folders = self.root / "var/lib/pacman/local"
        (folders / "pkg-a").mkdir(parents=True)
        pw = SimpleNamespace(pw_uid=4242, pw_dir=str(self.root / "home/fixture"), pw_name="fixture")
        with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
             patch("falsicore.collectors.os.geteuid", return_value=4242), \
             patch("falsicore.collectors.os.getuid", return_value=4242):
            audit = Audit("user", target_user="fixture", root=self.root, profile="deep")
        audit.managers = lambda: ["pacman"]
        audit._repo_config_files = lambda gaps: []
        audit.packages()
        row = next(r for r in audit.coverage if r["check"] == "packages")
        self.assertEqual(row["status"], "PARTIAL")
        self.assertIn("PARSE_UNSUPPORTED", row["reason_codes"])
        self.assertEqual(audit.stats["package_integrity"]["pacman"]["reference_db_omissions"]["PARSE_UNSUPPORTED"], 1)


if __name__ == "__main__":
    unittest.main()
