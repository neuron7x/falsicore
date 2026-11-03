"""FC-15/FC-30 and FC-14: exact package reference and offline verdict falsifiers.

All files are artificial package databases in a temporary tree; no host
metadata or production malware samples are used.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import collectors, detectors, packages
from falsicore.collectors import Audit, Gaps


class PackageReferenceFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.audit = Audit.__new__(Audit)
        self.audit.root = self.root
        self.audit.stats = {}
        self.audit._dpkg_index = None
        self.audit._pacman_index = None
        self.audit._package_db_gaps = {}
        self.info = self.root / "var/lib/dpkg/info"
        self.info.mkdir(parents=True)
        self.status = self.root / "var/lib/dpkg/status"
        self.status.write_text("")
        self.local = self.root / "var/lib/pacman/local"
        self.local.mkdir(parents=True)

    def md5file(self, name, body):
        p = self.info / (name + ".md5sums")
        p.write_bytes(body)
        return p

    def pacman_folder(self):
        folder = self.local / "pkg-v1"
        folder.mkdir()
        return folder


class DpkgReferenceFalsifiers(PackageReferenceFixture):
    def test_unreadable_dpkg_directory_records_read_failure(self):
        with patch.object(Path, "glob", side_effect=OSError("directory unavailable")):
            self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/sh"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["READ_FAILED"], 1)

    def test_unreadable_dpkg_index_file_records_read_failure(self):
        target = self.md5file("a", b"a" * 32 + b"  bin/a\n")
        original = collectors.safe_read

        def unreadable(path, bound):
            if path == target:
                return None, "PERMISSION_DENIED"
            return original(path, bound)

        with patch.object(collectors, "safe_read", side_effect=unreadable):
            self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/a"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["READ_FAILED"], 1)

    def test_exact_record_count_cap_does_not_report_an_omission(self):
        self.md5file("a", b"a" * 32 + b"  bin/a\n")
        self.md5file("b", b"b" * 32 + b"  bin/b\n")
        with patch.object(collectors, "DPKG_DB_MAX_RECORDS", 2):
            self.assertEqual(self.audit._dpkg_md5(self.root / "bin/b"), "b" * 32)
        self.assertNotIn("ENUMERATION_LIMIT",
                         self.audit._package_db_gaps.get("dpkg", {}))

    def test_exact_total_byte_cap_is_complete(self):
        body = b"a" * 32 + b"  bin/a\n"
        self.md5file("a", body)
        with patch.object(collectors, "DPKG_DB_MAX_BYTES", len(body)):
            self.assertEqual(self.audit._dpkg_md5(self.root / "bin/a"), "a" * 32)
        self.assertNotIn("ENUMERATION_LIMIT",
                         self.audit._package_db_gaps.get("dpkg", {}))

    def test_one_byte_under_data_size_is_an_enumeration_limit(self):
        body = b"a" * 32 + b"  bin/a\n"
        self.md5file("a", body)
        with patch.object(collectors, "DPKG_DB_MAX_BYTES", len(body) - 1):
            self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/a"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["ENUMERATION_LIMIT"], 1)

    def test_invalid_digest_must_not_enter_reference_index(self):
        self.md5file("evil", b"z" * 32 + b"  bin/evil\n")
        self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/evil"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["MALFORMED_INPUT"], 1)

    def test_nonempty_malformed_row_is_counted_not_silently_lost(self):
        self.md5file("bad", b"not-an-md5-record\n")
        self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/bad"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["MALFORMED_INPUT"], 1)

    def test_oversized_status_metadata_is_input_truncation_not_read_failure(self):
        original = collectors.safe_read

        def oversized_status(path, bound):
            if path == self.status:
                return None, "TOO_LARGE"
            return original(path, bound)

        with patch.object(collectors, "safe_read", side_effect=oversized_status):
            self.assertIsNone(self.audit._dpkg_md5(self.root / "bin/unknown"))
        self.assertEqual(self.audit._package_db_gaps["dpkg"]["INPUT_TRUNCATED"], 1)
        self.assertNotIn("READ_FAILED", self.audit._package_db_gaps["dpkg"])


class PacmanReferenceFalsifiers(PackageReferenceFixture):
    def test_unreadable_local_database_is_an_explicit_read_gap(self):
        self.local.rmdir()
        self.assertEqual(self.audit._pacman_records(), {})
        self.assertEqual(self.audit._package_db_gaps["pacman"]["READ_FAILED"], 1)

    def test_exact_package_count_cap_is_not_an_omission(self):
        self.pacman_folder()
        with patch.object(collectors, "PACKAGE_DB_MAX_RECORDS", 1):
            self.assertEqual(self.audit._pacman_records(), {})
        self.assertNotIn("ENUMERATION_LIMIT",
                         self.audit._package_db_gaps.get("pacman", {}))

    def test_exact_decompressed_byte_cap_is_not_an_omission(self):
        self.pacman_folder()
        payload = b"fixture-pacman-data"
        with patch.object(collectors, "PACKAGE_DB_MAX_BYTES", len(payload)), \
             patch.object(self.audit, "_read_mtree", return_value=payload), \
             patch.object(packages, "parse_pacman_mtree", return_value=({}, {})):
            self.assertEqual(self.audit._pacman_records(), {})
        self.assertNotIn("ENUMERATION_LIMIT",
                         self.audit._package_db_gaps.get("pacman", {}))

    def test_exceeded_decompressed_byte_cap_records_omitted_package(self):
        self.pacman_folder()
        payload = b"fixture-pacman-data"
        with patch.object(collectors, "PACKAGE_DB_MAX_BYTES", len(payload) - 1), \
             patch.object(self.audit, "_read_mtree", return_value=payload), \
             patch.object(packages, "parse_pacman_mtree", return_value=({}, {})):
            self.assertEqual(self.audit._pacman_records(), {})
        self.assertEqual(self.audit._package_db_gaps["pacman"]["ENUMERATION_LIMIT"], 1)

    def test_malformed_mtree_record_count_is_preserved(self):
        self.pacman_folder()
        with patch.object(self.audit, "_read_mtree", return_value=b"fixture"), \
             patch.object(packages, "parse_pacman_mtree", return_value=({}, {"malformed": 3})):
            self.assertEqual(self.audit._pacman_records(), {})
        self.assertEqual(self.audit._package_db_gaps["pacman"]["MALFORMED_INPUT"], 3)

    def test_missing_malformed_count_must_not_create_a_false_gap(self):
        self.pacman_folder()
        with patch.object(self.audit, "_read_mtree", return_value=b"fixture"), \
             patch.object(packages, "parse_pacman_mtree", return_value=({}, {})):
            self.assertEqual(self.audit._pacman_records(), {})
        self.assertNotIn("MALFORMED_INPUT",
                         self.audit._package_db_gaps.get("pacman", {}))


class EvalTrustAndOfflineVerdictFalsifiers(unittest.TestCase):
    def test_only_zero_unresolved_non_eval_sites_allows_attested_generator(self):
        audit = Audit.__new__(Audit)
        audit.stats = {}
        audit.source = lambda source: "synthetic-source"
        audit._attested_program = lambda name: "/usr/bin/dircolors"
        analysis = {
            "limitations": ["EXPANSION_NOT_RESOLVED"],
            "qualified_eval_sites": ["dircolors"],
            "unresolved_non_eval_sites": 0,
            "unresolved_expansions": 1,
        }
        gaps = Gaps()
        audit._shell_limit(analysis, "synthetic-shellrc", b"synthetic", gaps)
        self.assertEqual(gaps.limits["EVAL_OF_ATTESTED_PROGRAM_OUTPUT"], 1)
        self.assertNotIn("PARSE_UNSUPPORTED", gaps.incomplete)
        analysis["unresolved_non_eval_sites"] = 1
        gaps = Gaps()
        audit._shell_limit(analysis, "synthetic-shellrc", b"synthetic", gaps)
        self.assertEqual(gaps.incomplete["PARSE_UNSUPPORTED"], 1)
        self.assertNotIn("EVAL_OF_ATTESTED_PROGRAM_OUTPUT", gaps.limits)

    def test_skipped_without_offline_scope_evidence_is_inconclusive(self):
        coverage = []
        for check in ("processes", "network", "persistence", "browsers",
                      "auth", "packages", "crossview"):
            skip = check in ("processes", "network", "crossview")
            offline_proven = check in ("network", "crossview")
            coverage.append({
                "check": check,
                "status": "SKIPPED" if skip else "COMPLETED",
                "reason_codes": {},
                "scope_limits": {"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1}
                if offline_proven else {},
            })
        self.assertEqual(detectors.interpret_verdict([], coverage),
                         "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")
        coverage[0]["scope_limits"]["LIVE_ONLY_NOT_IN_OFFLINE_IMAGE"] = 1
        self.assertEqual(detectors.interpret_verdict([], coverage),
                         "NO_COMPROMISE_INDICATORS_OBSERVED")


if __name__ == "__main__":
    unittest.main()
