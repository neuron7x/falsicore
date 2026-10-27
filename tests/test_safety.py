import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore.safety import (safe_read, checked_executable, minimal_env,
                              create_run_directory, exclusive_write, run_command)
from falsicore.report import verify_reports

class SafetyTests(unittest.TestCase):
    def test_no_shell_executable(self):
        with self.assertRaises(ValueError):
            checked_executable("bash")

    def test_no_curl(self):
        with self.assertRaises(ValueError):
            checked_executable("curl")

    def test_no_python_execution(self):
        with self.assertRaises(ValueError):
            checked_executable("python3")

    def test_empty_env_no_secrets(self):
        e = minimal_env()
        self.assertNotIn("HOME", e)
        self.assertNotIn("LD_PRELOAD", e)
        self.assertNotIn("PYTHONPATH", e)

    def test_run_uname(self):
        res = run_command("uname", ["-r"])
        self.assertEqual(res["status"], "COMPLETED")
        self.assertTrue(res["stdout"])

    def test_nul_arg_rejected(self):
        with self.assertRaises(ValueError):
            run_command("uname", ["bad\x00arg"])

    def test_timeout_bad(self):
        with self.assertRaises(ValueError):
            run_command("uname", [], timeout=181)

    def test_run_output_bounded(self):
        r = run_command("uname", ["-a"], limit=4)
        self.assertEqual(r["status"], "PARTIAL")
        self.assertTrue(r["truncated"])
        self.assertLessEqual(len(r["stdout"]), 4)

    def test_private_run_dir(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "private"
            new = create_run_directory(base)
            self.assertEqual(new.stat().st_mode & 0o777, 0o700)
            self.assertEqual(base.stat().st_mode & 0o777, 0o700)

    def test_shared_output_base_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "out"
            base.mkdir(mode=0o777)
            base.chmod(0o755)
            with self.assertRaises(PermissionError):
                create_run_directory(base)

    def test_symlink_output_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base"
            base.mkdir(mode=0o700)
            link = Path(td) / "link"
            link.symlink_to(base, target_is_directory=True)
            with self.assertRaises(PermissionError):
                create_run_directory(link)

    def test_symlink_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            original = Path(td) / "file"
            original.write_text("private")
            link = Path(td) / "link"
            link.symlink_to(original)
            content, status = safe_read(link)
            self.assertIsNone(content)
            self.assertEqual(status, "SYMLINK_OR_NOT_DIRECTORY")

    def test_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "fifo"
            os.mkfifo(f)
            content, status = safe_read(f)
            self.assertIsNone(content)
            self.assertEqual(status, "NOT_REGULAR")

    def test_limit(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "large"
            f.write_bytes(b"1" * 100)
            raw, status = safe_read(f, 20)
            self.assertIsNone(raw)
            self.assertEqual(status, "TOO_LARGE")

    def test_exclusive_write(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test"
            exclusive_write(path, "hello")
            with self.assertRaises(FileExistsError):
                exclusive_write(path, "overwrite")
            self.assertEqual(path.read_text(), "hello")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_manifest_refuses_escape(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            (folder / "evidence_manifest.sha256").write_text("0"*64 + "  ../secret\n")
            out = verify_reports(folder)
            self.assertFalse(out["verified"])

    def test_manifest_refuses_missing(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                verify_reports(Path(td))

    def test_manifest_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            inside = parent / "real"
            inside.mkdir()
            (inside / "evidence_manifest.sha256").write_text("")
            link = parent / "link"
            link.symlink_to(inside, target_is_directory=True)
            with self.assertRaises(ValueError):
                verify_reports(link)
