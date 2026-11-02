"""Exact-equality and adjacent-invalid ZIP size-limit mutation falsifiers.

Historical whole-package survivors: bundle:31:2, bundle:36:3,
bundle:40:2 and bundle:49:1 (strict > mutated to >=).
Only synthetic, locally generated ZIPs are read; no scan or elevated access.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from falsicore import bundle


class BundleExactSizeBoundaryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.archive = Path(temp.name) / "synthetic.pyz"

    def make_archive(self, members: dict[str, bytes]) -> int:
        manifest = {
            "schema": "falsicore.bundle.v1",
            "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in members.items()},
        }
        manifest_raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
        with ZipFile(self.archive, "w", compression=ZIP_DEFLATED) as stream:
            for name, data in members.items():
                stream.writestr(name, data)
            stream.writestr(bundle.MANIFEST, manifest_raw)
        return len(manifest_raw) + sum(map(len, members.values()))

    def test_exact_member_count_160_is_accepted(self):
        members = {f"benign-{index:03d}.txt": b"" for index in range(bundle.MAX_MEMBERS - 1)}
        self.make_archive(members)
        self.assertEqual(bundle.read_verified_bundle(self.archive), members)

    def test_count_161_is_rejected(self):
        members = {f"benign-{index:03d}.txt": b"" for index in range(bundle.MAX_MEMBERS)}
        self.make_archive(members)
        with self.assertRaisesRegex(ValueError, "excessive bundle size"):
            bundle.read_verified_bundle(self.archive)

    def test_exact_expanded_limit_is_accepted(self):
        payload = {"zeros.dat": b"\x00" * 4096}
        total = self.make_archive(payload)
        self.assertLess(self.archive.stat().st_size, total)
        with patch.object(bundle, "MAX_TOTAL", total):
            self.assertEqual(bundle.read_verified_bundle(self.archive), payload)

    def test_expanded_total_one_byte_over_limit_is_rejected(self):
        total = self.make_archive({"zeros.dat": b"\x00" * 4096})
        with patch.object(bundle, "MAX_TOTAL", total - 1):
            with self.assertRaisesRegex(ValueError, "Expanded bundle size limit"):
                bundle.read_verified_bundle(self.archive)

    def test_exact_member_byte_limit_is_accepted(self):
        payload = {"benign.dat": b"\x00" * 4096}
        self.make_archive(payload)
        with patch.object(bundle, "MAX_MEMBER", 4096):
            self.assertEqual(bundle.read_verified_bundle(self.archive), payload)

    def test_member_one_byte_above_limit_is_rejected(self):
        self.make_archive({"benign.dat": b"\x00" * 4096})
        with patch.object(bundle, "MAX_MEMBER", 4095):
            with self.assertRaisesRegex(ValueError, "Unsafe bundle member"):
                bundle.read_verified_bundle(self.archive)

    def test_exact_encoded_file_limit_is_accepted_on_fstat_boundary(self):
        self.make_archive({"benign.dat": b"\x00" * 4096})
        original_fstat = bundle.os.fstat
        # Bound the actual checked file descriptor, not an unused Path.stat.
        # The 20 MiB threshold is an independent contract oracle.
        def reported_size(fd):
            info = original_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_size=20 * 1024 * 1024)

        with patch.object(bundle.os, "fstat", reported_size):
            self.assertEqual(bundle.read_verified_bundle(self.archive),
                             {"benign.dat": b"\x00" * 4096})

    def test_encoded_file_one_byte_above_limit_is_rejected_on_fstat_boundary(self):
        self.make_archive({"benign.dat": b"\x00" * 4096})
        original_fstat = bundle.os.fstat

        def reported_size(fd):
            info = original_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_size=20 * 1024 * 1024 + 1)

        with patch.object(bundle.os, "fstat", reported_size):
            with self.assertRaisesRegex(ValueError, "Application size limit exceeded"):
                bundle.read_verified_bundle(self.archive)


if __name__ == "__main__":
    unittest.main()
