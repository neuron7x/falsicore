"""Portable application integrity, extraction and CLI safety boundaries."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

from falsicore import bundle
from tools.build_app import bundle_bytes


class PortableBundleContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "falsicore.pyz"
        self.payload = {"README.md": b"test", "run.sh": b"#!/bin/sh\nexit 0\n"}
        self.app.write_bytes(bundle_bytes(self.payload))

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_integrity(self):
        result = bundle.read_verified_bundle(self.app)
        self.assertEqual(result["README.md"], b"test")

    def test_reproducible_bytes(self):
        self.assertEqual(bundle_bytes(self.payload), bundle_bytes(dict(reversed(list(self.payload.items())))))

    def test_corrupt_member(self):
        with ZipFile(self.app) as z:
            parts = {n: z.read(n) for n in z.namelist()}
        parts["README.md"] = b"tampered"
        with ZipFile(self.app, "w") as z:
            for k, v in parts.items():
                z.writestr(k, v)
        with self.assertRaisesRegex(ValueError, "checksum"):
            bundle.read_verified_bundle(self.app)

    def test_missing_manifest(self):
        with ZipFile(self.app, "w") as z:
            z.writestr("README.md", "x")
        with self.assertRaisesRegex(ValueError, "manifest"):
            bundle.read_verified_bundle(self.app)

    def test_added_untracked_member(self):
        with ZipFile(self.app, "a") as z:
            z.writestr("unexpected.py", "")
        with self.assertRaisesRegex(ValueError, "match manifest"):
            bundle.read_verified_bundle(self.app)

    def test_traversal_member(self):
        self.app.write_bytes(bundle_bytes({"../escaped": b"x"}))
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            bundle.read_verified_bundle(self.app)
        self.assertFalse((self.root.parent / "escaped").exists())

    def test_symlink_app(self):
        link = self.root / "alias.pyz"
        link.symlink_to(self.app)
        with self.assertRaises(ValueError):
            bundle.read_verified_bundle(link)

    def test_duplicate_member(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with ZipFile(self.app, "a") as z:
                z.writestr("README.md", "duplicate")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            bundle.read_verified_bundle(self.app)

    def test_member_size_limit(self):
        with patch.object(bundle, "MAX_MEMBER", 1):
            with self.assertRaises(ValueError):
                bundle.read_verified_bundle(self.app)

    def test_application_size_limit(self):
        with patch.object(bundle, "MAX_TOTAL", 1):
            with self.assertRaises(ValueError):
                bundle.read_verified_bundle(self.app)

    def test_symlink_member(self):
        with ZipFile(self.app, "a") as z:
            info = ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "/etc/passwd")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            bundle.read_verified_bundle(self.app)

    def test_export_no_overwrite(self):
        destination = self.root / "source"
        payload = bundle.read_verified_bundle(self.app)
        bundle.export_source(payload, destination)
        with self.assertRaises(FileExistsError):
            bundle.export_source(payload, destination)
        self.assertEqual((destination / "README.md").read_bytes(), b"test")

    def test_export_permissions(self):
        destination = bundle.export_source(bundle.read_verified_bundle(self.app), self.root / "source")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((destination / "README.md").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((destination / "run.sh").stat().st_mode), 0o700)
        self.assertFalse((destination / "__main__.py").exists())

    def test_export_rejects_shared_parent(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o700)
        original_stat = Path.stat
        from types import SimpleNamespace
        def metadata(path, *args, **kwargs):
            if path == parent:
                return SimpleNamespace(st_uid=os.geteuid(), st_mode=stat.S_IFDIR | 0o777)
            return original_stat(path, *args, **kwargs)
        with patch.object(Path, "stat", metadata), self.assertRaises(PermissionError):
            bundle.export_source(self.payload, parent / "source")

    def test_export_rejects_symlink_parent(self):
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real)
        with self.assertRaises(PermissionError):
            bundle.export_source(self.payload, link / "source")

    def test_verify_cli(self):
        with patch("sys.argv", [str(self.app), "verify-app"]):
            self.assertEqual(bundle.main(), 0)

    def test_default_routes_to_user_scan(self):
        with patch("sys.argv", [str(self.app)]), patch("falsicore.cli.main", return_value=0) as cli:
            self.assertEqual(bundle.main(), 0)
            cli.assert_called_once_with(["scan", "--scope", "user", "--auto-compare"])

    def test_corruption_blocks_scan(self):
        self.app.write_bytes(b"not a zip")
        with patch("sys.argv", [str(self.app)]), patch("falsicore.cli.main") as cli:
            self.assertEqual(bundle.main(), 2)
            cli.assert_not_called()

    def test_scheduling_refused_for_portable(self):
        with patch("sys.argv", [str(self.app), "monitor", "enable"]):
            self.assertEqual(bundle.main(), 2)

    def test_export_cli(self):
        with patch("sys.argv", [str(self.app), "export-source", str(self.root / "new")]):
            self.assertEqual(bundle.main(), 0)

    def test_export_missing_argument(self):
        with patch("sys.argv", [str(self.app), "export-source"]):
            self.assertEqual(bundle.main(), 2)

    def test_selftest_is_explicit_not_default(self):
        with patch("sys.argv", [str(self.app), "self-test"]), patch.object(bundle, "self_test", return_value=0) as runner:
            self.assertEqual(bundle.main(), 0)
            runner.assert_called_once()

    def test_selftest_uses_bounded_executor(self):
        with patch("falsicore.bundle.run_test_suite", return_value={"status": "COMPLETED", "stdout": "OK"}) as runner:
            self.assertEqual(bundle.self_test(self.payload), 0)
            checkout = runner.call_args.args[0]
            self.assertFalse(checkout.exists())

    def test_selftest_runner_is_fixed_and_isolated(self):
        from falsicore.safety import run_test_suite
        with patch("falsicore.safety._run_bounded", return_value={"status": "COMPLETED"}) as runner:
            run_test_suite(self.root)
            executable, args, timeout, limit = runner.call_args.args
            self.assertEqual(args[:2], ["-I", "-B"])
            self.assertEqual(timeout, 180)
            self.assertEqual(limit, 1048576)


if __name__ == "__main__":
    unittest.main()
