"""Falsify portable bundle schema bypass without weakening benign checks.

The historical full-package mutant bundle:52:2:boolop:swap replaces the
manifest-type-or-version guard with AND. A well-formed ZIP whose schema is
wrong or missing must never be accepted merely because its hashes match.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from falsicore import bundle


class BundleManifestSchemaGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "candidate.pyz"

    def _write(self, *, schema: str | None = "falsicore.bundle.v1", corrupt_digest: bool = False):
        body = b"synthetic benign bytes"
        digest = hashlib.sha256(body).hexdigest()
        manifest: dict[str, object] = {"sha256": {"README.txt": "0" * 64 if corrupt_digest else digest}}
        if schema is not None:
            manifest["schema"] = schema
        with ZipFile(self.archive, "w") as archive:
            archive.writestr("README.txt", body)
            archive.writestr(bundle.MANIFEST, json.dumps(manifest, sort_keys=True))
        return body

    def test_rejects_unsupported_version_even_when_digest_valid(self):
        self._write(schema="falsicore.bundle.v2")
        with self.assertRaisesRegex(ValueError, "Unsupported bundle manifest"):
            bundle.read_verified_bundle(self.archive)

    def test_rejects_missing_version_even_when_digest_valid(self):
        self._write(schema=None)
        with self.assertRaisesRegex(ValueError, "Unsupported bundle manifest"):
            bundle.read_verified_bundle(self.archive)

    def test_benign_exact_version_and_digest_accepted(self):
        body = self._write()
        self.assertEqual(bundle.read_verified_bundle(self.archive), {"README.txt": body})

    def test_benign_version_with_corrupt_digest_remains_rejected(self):
        self._write(corrupt_digest=True)
        with self.assertRaisesRegex(ValueError, "Bundle member checksum mismatch"):
            bundle.read_verified_bundle(self.archive)


if __name__ == "__main__":
    unittest.main()
