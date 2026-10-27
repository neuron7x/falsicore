"""Release-independent trust-boundary checks (stdlib only)."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from falsicore.collectors import Audit, _allowed_audit_invocation
from falsicore.report import write_reports, verify_reports
from tools import build_release


class FixedReadOnlyAuditPolicy(unittest.TestCase):
    def test_all_actual_probe_shapes_have_explicit_allowance(self):
        accepted = [
            ("uname", ["-r"]), ("ss", ["-H", "-tuna", "-p"]),
            ("crontab", ["-l"]), ("crontab", ["-l", "-u", "nobody"]),
            ("journalctl", ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "--since", "2026-10-27 00:00:00 UTC",
                            "--lines", "20000", "--no-pager", "--output=json",
                            "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"]),
            ("journalctl", ["_TRANSPORT=kernel", "--since", "2026-10-27 00:00:00 UTC",
                            "--lines", "5000", "--no-pager", "--output=json",
                            "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"]),
            ("dpkg", ["--verify"]), ("aa-status", ["--enabled"]),
            ("mokutil", ["--sb-state"]),
        ]
        for name, args in accepted:
            self.assertTrue(_allowed_audit_invocation(name, args), (name, args))

    def test_mutation_and_command_injection_options_are_refused(self):
        rejected = [
            ("systemctl", ["stop", "ssh.service"]),
            ("dpkg", ["--remove", "libc6"]),
            ("crontab", ["-r"]),
            ("crontab", ["-l", "-u", "root;touch /tmp/pwn"]),
            ("journalctl", ["--vacuum-time=1s"]),
            ("uname", ["-a", "--help"]),
            ("ss", ["-K", "dst", "1.2.3.4"]),
        ]
        for name, args in rejected:
            self.assertFalse(_allowed_audit_invocation(name, args), (name, args))

    def test_mutating_probe_never_reaches_command_runner(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            audit = Audit(scope="user", target_user="nobody")
        with patch("falsicore.collectors.run_command") as executed:
            with self.assertRaises(PermissionError):
                audit.command("dpkg", ["--remove", "libc6"])
        executed.assert_not_called()


class AtomicDistributionContracts(unittest.TestCase):
    def test_manifest_and_zip_use_exact_same_single_read_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            source = root / "README.md"
            old = b"source-v1\n"
            source.write_bytes(old)
            destination = Path(td) / "release.zip"
            actual_reader = build_release._read_safe_source
            calls = []
            def mutate_after_read(path):
                result = actual_reader(path)
                calls.append(path.name)
                path.write_bytes(b"source-v2\n")
                return result
            with patch.object(build_release, "ROOT", root), \
                 patch.object(build_release, "_read_safe_source", side_effect=mutate_after_read):
                digest, count = build_release.build(destination)
                prefix = build_release.archive_prefix()
            self.assertEqual(count, 2)
            self.assertEqual(calls, ["README.md"])
            self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), digest)
            with ZipFile(destination) as z:
                # The archive prefix is constant (C-10), not the checkout folder name.
                self.assertEqual(z.read(prefix + "README.md"), old)
                manifest = z.read(prefix + "SOURCE_MANIFEST.sha256").decode()
                self.assertEqual(manifest, hashlib.sha256(old).hexdigest() + "  README.md\n")
                self.assertEqual(z.testzip(), None)
            self.assertEqual(source.read_bytes(), b"source-v2\n")
            self.assertFalse((root / "SOURCE_MANIFEST.sha256").exists(), "build must not edit the tree")

    def test_build_does_not_replace_existing_release(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            (root / "README.md").write_text("placeholder")
            destination = Path(td) / "release.zip"
            destination.write_text("already published")
            with patch.object(build_release, "ROOT", root):
                with self.assertRaises(FileExistsError):
                    build_release.build(destination)
            self.assertEqual(destination.read_text(), "already published")

    def test_release_zip_is_bitwise_repeatable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            (root / "README.md").write_bytes(b"deterministic\n")
            d1 = Path(td) / "one.zip"
            d2 = Path(td) / "two.zip"
            with patch.object(build_release, "ROOT", root):
                a = build_release.build(d1)
                b = build_release.build(d2)
            self.assertEqual(a,b)
            self.assertEqual(d1.read_bytes(),d2.read_bytes())

    def test_archive_bytes_do_not_depend_on_checkout_folder_name(self):
        with tempfile.TemporaryDirectory() as td:
            digests = []
            for folder in ("falsicore", "renamed checkout ✓"):
                root = Path(td) / folder
                (root / "falsicore").mkdir(parents=True)
                (root / "falsicore" / "__init__.py").write_text('__version__ = "9.9.9"\n')
                with patch.object(build_release, "ROOT", root):
                    digests.append(build_release.build(Path(td) / (folder + ".zip"))[0])
            self.assertEqual(digests[0], digests[1])


class PublicReportRedactionContracts(unittest.TestCase):
    def test_private_source_stays_in_private_index_only_and_html_escapes(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "run"
            folder.mkdir(mode=0o700)
            with patch("falsicore.collectors.os.geteuid", return_value=1001), \
                 patch("falsicore.collectors.os.getuid", return_value=1001):
                audit = Audit(scope="user", target_user="nobody")
            private = "/home/very-secret/credentials.json"
            audit.finding("TEST_INDICATOR", "high", "synthetic only", private,
                          {"present": True})
            audit.checked("browsers", "PARTIAL", "<script>untrusted-text</script>", reasons=["MALFORMED_INPUT"])
            write_reports(folder, audit)
            self.assertTrue(verify_reports(folder)["verified"])
            self.assertIn(private, (folder / "private_index.json").read_text())
            for name in ("summary.json", "findings.json", "report.md", "dashboard.html", "coverage_matrix.json"):
                self.assertNotIn(private, (folder/name).read_text(), name)
            html = (folder / "dashboard.html").read_text()
            self.assertNotIn("<script>untrusted-text</script>", html)
            self.assertIn("&lt;script&gt;untrusted-text&lt;/script&gt;", html)


if __name__ == "__main__":
    unittest.main()
