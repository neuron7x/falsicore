"""Release boundary for the verification program and imported evidence."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from tools import build_release

EXPECTED_FILES = {
    "assurance/check_registry.py",
    "assurance/test_check_registry.py",
    "docs/verification/README.md",
    "docs/verification/tasks.json",
    "docs/verification/source/README.txt",
    "docs/verification/source/AUDIT_CHECKSUMS.txt",
    "docs/verification/source/FINDINGS.json",
    "docs/verification/source/FALSICORE_VERIFICATION_ACT.md",
    "docs/VERIFICATION_PROGRAM.md",
}


class VerificationBundleTest(unittest.TestCase):
    def test_archive_contains_exact_required_files_and_matching_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            for name in EXPECTED_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("fixture:" + name).encode())
            archive = Path(td) / "bundle.zip"
            with patch.object(build_release, "ROOT", root):
                _, count = build_release.build(archive)
                prefix = build_release.archive_prefix()
            with ZipFile(archive) as z:
                expected = {prefix + n for n in EXPECTED_FILES}
                expected.add(prefix + "SOURCE_MANIFEST.sha256")
                self.assertEqual(set(z.namelist()), expected)
                self.assertEqual(count, len(EXPECTED_FILES) + 1)
                manifest = z.read(prefix + "SOURCE_MANIFEST.sha256").decode()
                for name in EXPECTED_FILES:
                    data = z.read(prefix + name)
                    self.assertEqual(data, ("fixture:" + name).encode())
                    self.assertIn(hashlib.sha256(data).hexdigest() + "  " + name + "\n", manifest)

    def test_unknown_or_sensitive_files_fail_packaging(self):
        for name in ("assurance/secrets.py", "assurance/data/token.txt",
                     "docs/verification/private.json", "docs/verification/source/auth.json",
                     "docs/verification/source/nested/FINDINGS.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td) / "root"
                path = root / name
                path.parent.mkdir(parents=True)
                path.write_text("private", encoding="utf-8")
                archive = Path(td) / "bundle.zip"
                with patch.object(build_release, "ROOT", root), self.assertRaisesRegex(
                    ValueError, "Unexpected release payload"
                ):
                    build_release.build(archive)
                self.assertFalse(archive.exists())


if __name__ == "__main__":
    unittest.main()
