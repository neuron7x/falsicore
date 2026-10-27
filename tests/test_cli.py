import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from falsicore import cli
from falsicore.report import write_reports


class CLITests(unittest.TestCase):
    def fake(self):
        return SimpleNamespace(scope="user", target_user="fixture", home=Path("/tmp"),
                               findings=[], scan=lambda: None,
                               coverage=[{"check":n,"status":"COMPLETED","details":"fake"} for n in ("processes","network","persistence","browsers","auth","packages")],
                               commands=[],stats={},private_index={},dropped_findings=0,
                               baseline={"listeners": [], "process_exe_hashes": [], "systemd_units": [], "cron_entry_hashes":[],"ssh_key_fingerprints":[],"browser_extensions":[],"native_hosts":[]})

    def test_doctor(self):
        output=io.StringIO()
        with redirect_stdout(output):
            value=cli.main(["doctor"])
        self.assertEqual(value,0)
        self.assertIn("NO automatic sudo",output.getvalue())

    def test_version(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_cli_scan(self):
        with tempfile.TemporaryDirectory() as td, patch("falsicore.cli.Audit",return_value=self.fake()), \
             patch("falsicore.cli.pwd.getpwuid",return_value=SimpleNamespace(pw_name="fixture")), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["scan","--scope","user","--target-user","fixture","--output-base", str(Path(td)/"base")]),0)
            self.assertIn("NO_COMPROMISE_INDICATORS_OBSERVED", out.getvalue())

    def test_cli_scan_explicit_wrong_user(self):
        with patch("falsicore.cli.pwd.getpwuid",return_value=SimpleNamespace(pw_name="fixture")), redirect_stderr(io.StringIO()) as out:
            self.assertEqual(cli.main(["scan","--target-user","other"]),2)
            self.assertIn("PermissionError", out.getvalue())

    def test_cli_bad_output_parent(self):
        with tempfile.TemporaryDirectory() as td, patch("falsicore.cli.Audit",return_value=self.fake()), \
             redirect_stderr(io.StringIO()) as out:
            base=Path(td)/"bad"
            base.mkdir()
            base.chmod(0o755)
            self.assertEqual(cli.main(["scan","--output-base",str(base)]),2)
            self.assertIn("PermissionError",out.getvalue())

    def test_cli_verify_good(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            write_reports(p,self.fake())
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(cli.main(["verify",td]),0)
            self.assertIn("VERIFIED",out.getvalue())

    def test_cli_verify_failure(self):
        with tempfile.TemporaryDirectory() as td,redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["verify",td]),2)

    def test_cli_verify_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            write_reports(p,self.fake())
            (p/"report.md").write_text("tamper")
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(cli.main(["verify",td]),2)
            self.assertIn("INVALID",out.getvalue())

    def test_cli_version_contract(self):
        p=cli.parser()
        self.assertIsNotNone(p)

    def test_cli_refuses_root_user_scan(self):
        with tempfile.TemporaryDirectory() as td, \
             patch("falsicore.cli.Audit",side_effect=PermissionError("root not allowed")), \
             redirect_stderr(io.StringIO()) as out:
            self.assertEqual(cli.main(["scan","--output-base",td]),2)
            self.assertIn("root not allowed",out.getvalue())
