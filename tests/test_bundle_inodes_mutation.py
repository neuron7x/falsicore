"""Pin portable bundle identity across adversarial pathname replacement.

The old check-stat-open sequence accepted an attacker-selected, internally
consistent bundle substituted at ZipFile open. All test ZIPs are synthetic.
"""
from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile

from falsicore import bundle


class BundlePinnedInodeControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.primary = root / "primary.pyz"
        self.alternate = root / "alternate.pyz"
        self._make(self.primary, b"original synthetic bytes")
        self._make(self.alternate, b"replacement synthetic bytes")

    @staticmethod
    def _make(path: Path, raw: bytes) -> None:
        manifest = {"schema": "falsicore.bundle.v1",
                    "sha256": {"payload.txt": hashlib.sha256(raw).hexdigest()}}
        with ZipFile(path, "w") as archive:
            archive.writestr("payload.txt", raw)
            archive.writestr(bundle.MANIFEST, json.dumps(manifest, sort_keys=True))

    def test_path_swapped_after_preflight_preserves_original_inode(self):
        real_zip = bundle.zipfile.ZipFile
        swaps = []

        def swap_at_open(source, *args, **kwargs):
            if not swaps:
                self.primary.unlink()
                self.primary.symlink_to(self.alternate)
                swaps.append(True)
            return real_zip(source, *args, **kwargs)

        with patch.object(bundle.zipfile, "ZipFile", side_effect=swap_at_open):
            actual = bundle.read_verified_bundle(self.primary)
        self.assertEqual(swaps, [True])
        self.assertEqual(actual, {"payload.txt": b"original synthetic bytes"})

    def test_benign_unmodified_regular_bundle_remains_accepted(self):
        self.assertEqual(bundle.read_verified_bundle(self.primary),
                         {"payload.txt": b"original synthetic bytes"})

    def test_initial_symlink_refused_with_existing_valueerror_contract(self):
        self.primary.unlink()
        self.primary.symlink_to(self.alternate)
        with self.assertRaisesRegex(ValueError, "regular file, not a symlink"):
            bundle.read_verified_bundle(self.primary)

    def test_pinned_descriptor_nonregular_metadata_refused(self):
        fake = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_size=0)
        with patch.object(bundle.os, "fstat", return_value=fake):
            with self.assertRaisesRegex(ValueError, "regular file"):
                bundle.read_verified_bundle(self.primary)

    def test_pinned_descriptor_oversized_metadata_refused(self):
        fake = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                               st_size=bundle.MAX_TOTAL + 1)
        with patch.object(bundle.os, "fstat", return_value=fake):
            with self.assertRaisesRegex(ValueError, "size limit"):
                bundle.read_verified_bundle(self.primary)


if __name__ == "__main__":
    unittest.main()
