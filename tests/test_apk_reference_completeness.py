"""APK reference-set completeness: malformed, truncated and benign synthetic indexes.

All input is constructed under a disposable root; no live APK database is read.
"""
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import collectors, packages
from falsicore.collectors import Audit


class ApkReferenceCompleteness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.index = self.root / "lib/apk/db/installed"
        self.index.parent.mkdir(parents=True)
        self.binary = self.root / "usr/bin/good"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"trusted fixture bytes")
        digest = base64.b64encode(hashlib.sha256(self.binary.read_bytes()).digest()).decode("ascii")
        self.record = f"P:fixture\nV:1.0\nF:usr/bin\nR:good\nZ:Q2{digest}\n\n".encode()
        pw = SimpleNamespace(pw_uid=4242, pw_dir=str(self.root / "home/fixture"), pw_name="fixture")
        with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
             patch("falsicore.collectors.os.geteuid", return_value=4242), \
             patch("falsicore.collectors.os.getuid", return_value=4242):
            self.audit = Audit("user", target_user="fixture", root=self.root, profile="deep")
        self.audit.managers = lambda: ["apk"]
        self.audit._repo_config_files = lambda gaps: []

    def scan(self):
        self.audit.packages()
        row = next(item for item in self.audit.coverage if item["check"] == "packages")
        return row, self.audit.stats["package_integrity"]["apk"]

    def test_malformed_row_fails_closed_while_valid_reference_remains_checked(self):
        self.index.write_bytes(self.record.replace(b"\n\n", b"\nnot-an-apk-record\n\n"))
        row, review = self.scan()
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(row["reason_codes"].get("MALFORMED_INPUT"), 1)
        self.assertEqual(review["unparsed_lines"], 1)
        self.assertEqual(review["files_checked"], 1)
        self.assertEqual(review["content_changed_other_files"], 0)
        self.assertEqual(review["reference_lines_omitted"], 0)

    def test_parse_cap_exposes_number_of_omitted_reference_lines(self):
        self.index.write_bytes(self.record + self.record.replace(b"P:fixture", b"P:another"))
        with patch.object(packages, "APK_MAX_LINES", len(self.record.splitlines())):
            row, review = self.scan()
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(row["reason_codes"].get("ENUMERATION_LIMIT"), len(self.record.splitlines()))
        self.assertEqual(review["reference_lines_omitted"], len(self.record.splitlines()))
        self.assertTrue(review["truncated"])
        self.assertEqual(review["records"], 1)
        self.assertEqual(review["files_checked"], 1)

    def test_valid_untruncated_apk_is_completed_without_false_gap(self):
        self.index.write_bytes(self.record)
        with patch.object(packages, "APK_MAX_LINES", len(self.record.splitlines())):
            row, review = self.scan()
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["reason_codes"], {})
        self.assertEqual(review["files_checked"], 1)
        self.assertEqual(review["reference_lines_omitted"], 0)
        self.assertFalse(review["truncated"])

    def test_unreadable_installed_index_is_read_failure_not_completed(self):
        self.index.write_bytes(self.record)
        original = collectors.safe_read

        def unreadable(path, limit):
            if path == self.index:
                return None, "READ_FAILED"
            return original(path, limit)

        with patch.object(collectors, "safe_read", side_effect=unreadable):
            row, review = self.scan()
        self.assertEqual(row["status"], "PARTIAL")
        self.assertIn("READ_FAILED", row["reason_codes"])
        self.assertEqual(review["files_checked"], 0)

    def test_disappeared_installed_index_cannot_be_a_clean_verification(self):
        # The manager was selected before the database vanished (TOCTOU).
        row, review = self.scan()
        self.assertEqual(row["status"], "PARTIAL")
        self.assertIn("READ_FAILED", row["reason_codes"])
        self.assertEqual(review["records"], 0)


if __name__ == "__main__":
    unittest.main()
