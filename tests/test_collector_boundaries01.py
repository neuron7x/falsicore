"""Independent failure, observability, and profile-boundary regressions for 0.1.0."""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import collectors


class CollectorBoundaries(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.home = self.folder / "home"
        self.home.mkdir()
        fake = SimpleNamespace(pw_uid=42042, pw_dir=str(self.home))
        with patch.object(collectors.pwd, "getpwnam", return_value=fake), \
             patch.object(collectors.os, "geteuid", return_value=42042):
            self.a = collectors.Audit("user", target_user="fixture")
        self.a.command = lambda *_a, **_k: {
            "status": "COMPLETED", "stdout": "", "exit": 0, "elapsed_ms": 0,
            "truncated": False, "error": "",
        }

    def write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf8")
        return path

    def test_collector_rollback_discards_all_coverage_not_only_named_check(self):
        def good():
            self.a.checked("environment", "COMPLETED", "pre-existing valid coverage")
            self.a.stats["good"] = 1

        def bad():
            self.a.checked("environment", "COMPLETED", "misleading duplicate")
            self.a.checked("unrelated", "COMPLETED", "misleading nested check")
            self.a.finding("BAD_PARTIAL", "high", "test", "/tmp/sample")
            self.a.baseline["listeners"].append("temporary")
            self.a.stats["bad"] = True
            self.a.suspicious_exec_pids.add(999)
            raise OSError("simulated interruption")

        self.a.environment = good
        self.a.processes = bad
        for name in ("network", "persistence", "browsers", "auth", "packages", "kernel"):
            setattr(self.a, name, lambda n=name: self.a.checked(n, "COMPLETED", "fixture"))
        self.a.scan()
        checks = [entry["check"] for entry in self.a.coverage]
        self.assertEqual(checks.count("environment"), 1)
        self.assertNotIn("unrelated", checks)
        self.assertEqual(next(x for x in self.a.coverage if x["check"] == "processes")["status"], "FAILED")
        self.assertFalse(self.a.findings)
        self.assertEqual(self.a.baseline["listeners"], [])
        self.assertEqual(self.a.stats.get("good"), 1)
        self.assertNotIn("bad", self.a.stats)
        self.assertEqual(self.a.suspicious_exec_pids, set())

    def test_missing_coverage_from_collector_fail_closed(self):
        self.a.environment = lambda: None
        for name in ("processes", "network", "persistence", "browsers", "auth", "packages", "kernel"):
            setattr(self.a, name, lambda n=name: self.a.checked(n, "COMPLETED", "fixture"))
        self.a.scan()
        self.assertEqual(self.a.coverage[0]["status"], "FAILED")

    def test_collector_without_coverage_rolls_back_uncommitted_findings(self):
        def silent():
            self.a.finding("FALSE_EVIDENCE", "high", "fixture", "/tmp/record")
            self.a.stats["partial"] = 1
            self.a.checked("nested", "COMPLETED", "wrong scope")
            self.a.baseline["listeners"].append("partial")

        self.a.environment = silent
        for name in ("processes", "network", "persistence", "browsers", "auth", "packages", "kernel"):
            setattr(self.a, name, lambda n=name: self.a.checked(n, "COMPLETED", "fixture"))
        self.a.scan()
        self.assertEqual(self.a.coverage[0]["status"], "FAILED")
        self.assertFalse(self.a.findings)
        self.assertNotIn("partial", self.a.stats)
        self.assertEqual(self.a.baseline["listeners"], [])
        self.assertNotIn("nested", {x["check"] for x in self.a.coverage})

    def test_exhausted_budget_marks_all_collectors_skipped(self):
        self.a.over_budget = lambda: True
        self.a.scan()
        self.assertEqual(len(self.a.coverage), 8)
        self.assertTrue(all(c["status"] == "SKIPPED" for c in self.a.coverage))

    def test_command_budget_exhausted_does_not_start_subprocess(self):
        self.a.deadline = time.monotonic() - 1
        with patch.object(collectors, "run_command") as spy:
            result = collectors.Audit.command(self.a, "uname", ["-r"])
        self.assertEqual(result["status"], "SKIPPED")
        spy.assert_not_called()

    def test_command_budget_caps_subprocess_timeout(self):
        self.a.deadline = time.monotonic() + 0.4
        output = {"status": "COMPLETED", "stdout": "", "exit": 0,
                  "elapsed_ms": 1, "truncated": False, "error": ""}
        with patch.object(collectors, "run_command", return_value=output) as spy:
            collectors.Audit.command(self.a, "uname", ["-r"], timeout=200)
        self.assertLess(spy.call_args.kwargs["timeout"], 1)
        self.assertEqual(len(self.a.commands), 1)

    def test_environment_fallback_tracks_fixed_vendor_file(self):
        original = collectors.safe_read
        def readable(path, limit=1024):
            if str(path) == "/etc/os-release":
                return None, "SYMLINK"
            if str(path) == "/usr/lib/os-release":
                return b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu"\n', "COMPLETED"
            if str(path).startswith("/proc/sys/kernel/"):
                return b"1\n", "COMPLETED"
            return original(path, limit)
        with patch.object(collectors, "safe_read", side_effect=readable):
            self.a.environment()
        self.assertEqual(self.a.stats["host"]["os_release_source"], "/usr/lib/os-release")
        self.assertEqual(self.a.stats["host"]["os_release"]["ID"], "ubuntu")
        self.assertEqual(self.a.coverage[-1]["status"], "COMPLETED")

    def test_environment_flags_ssh_directory_group_permissions(self):
        (self.home / ".ssh").mkdir(mode=0o755)
        (self.home / ".ssh").chmod(0o755)
        with patch.object(collectors, "safe_read", return_value=(b"ID=ubuntu", "COMPLETED")):
            self.a.environment()
        self.assertIn("SSH_DIRECTORY_OVERPERMISSIVE", {x["rule"] for x in self.a.findings})

    def test_proc_missing_status_and_uid_does_not_claim_complete_coverage(self):
        proc = self.folder / "proc"
        proc.mkdir()
        (proc / "1").mkdir()
        self.write(proc / "1" / "status", "Name:\tfixture\n")
        (proc / "2").mkdir()
        self.a.proc_root = proc
        self.a.processes()
        self.assertEqual(self.a.findings, [])
        self.assertNotEqual(self.a.stats["processes"].get("processes_examined"), 2)

    def test_network_listener_without_owner_is_never_silent(self):
        self.a.command = lambda *_a, **_k: {"status": "COMPLETED", "stdout": "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*\n"}
        self.a.network()
        # User scope: other accounts' sockets cannot be attributed by design.
        self.assertEqual(self.a.coverage[-1]["scope_limits"], {"OTHER_ACCOUNTS_NOT_VISIBLE": 1})
        self.assertEqual(self.a.stats["network"]["listeners_without_process_identity"], 1)
        # System scope should see every owner: a missing one is an incompleteness.
        self.a.scope = "system"
        self.a.network()
        self.assertEqual(self.a.coverage[-1]["status"], "PARTIAL")
        self.assertEqual(self.a.coverage[-1]["reason_codes"], {"ATTRIBUTION_UNAVAILABLE": 1})

    def test_file_collection_refuses_symlinks_and_reports_gap(self):
        base = self.folder / "data"
        base.mkdir()
        self.write(base / "real.service", "fixture")
        (base / "link.service").symlink_to(base / "real.service")
        files, gap = self.a._files([base], extensions={".service"})
        # The link's target is enumerated inside the same root: covered, not a gap.
        self.assertFalse(gap)
        self.assertEqual(files, [base / "real.service"])
        outside = self.folder / "outside.service"
        self.write(outside, "fixture")
        (base / "escape.service").symlink_to(outside)
        files, gap = self.a._files([base], extensions={".service"})
        self.assertTrue(gap)
        self.assertEqual(files, [base / "real.service"])
        files2, gap2 = self.a._files([base / "link"], recursive=True)
        self.assertEqual(files2, [])
        self.assertFalse(gap2)

    def test_file_collection_limit_and_symlink_base(self):
        base = self.folder / "data"
        base.mkdir()
        for x in ("a.txt", "b.txt", "c.txt"):
            self.write(base / x, x)
        files, gap = self.a._files([base], limit=1)
        self.assertEqual(len(files), 1)
        self.assertTrue(gap)
        shortcut = self.folder / "alias"
        shortcut.symlink_to(base)
        self.assertEqual(self.a._files([shortcut]), ([], True))

    def test_mtime_correlation_is_only_temporal(self):
        now = dt.datetime.now(dt.timezone.utc)
        self.a.incident_at = now
        p = self.write(self.folder / "record.service", "fixture")
        self.assertTrue(self.a._mtime_near_incident(p))
        os.utime(p, (time.time() - 10 * 86400, time.time() - 10 * 86400))
        self.assertFalse(self.a._mtime_near_incident(p))
        self.assertIsNone(self.a._mtime_near_incident(self.folder / "absent"))

    def test_persistence_unreadable_ssh_symlink_is_gap(self):
        ssh = self.home / ".ssh"
        ssh.mkdir()
        self.write(self.folder / "outside", "ssh-ed25519 fake")
        (ssh / "authorized_keys").symlink_to(self.folder / "outside")
        self.a._files = lambda *_a, **_k: ([], False)
        with patch.object(collectors.os, "walk", return_value=iter(())):
            self.a.persistence()
        self.assertEqual(self.a.stats["persistence"]["ssh_unreadable"], 1)
        self.assertEqual(self.a.coverage[-1]["status"], "PARTIAL")

    def test_chromium_base_symlink_marks_incomplete(self):
        base = self.folder / "real"
        base.mkdir()
        link = self.folder / "alias"
        link.symlink_to(base)
        self.assertEqual(self.a._scan_chromium("browser", link), (0, 0, True))

    def test_firefox_disabled_addon_is_not_active_exposure(self):
        p = self.home / ".mozilla/firefox/a.default-release/extensions.json"
        self.write(p, json.dumps({"addons": [{"id":"x@test","type":"extension","userDisabled":True,
                                              "userPermissions":{"permissions":["cookies"],"origins":["<all_urls>"]}}]}))
        count, gap = self.a._scan_firefox()
        self.assertEqual((count, gap), (1, False))
        self.assertEqual(self.a.findings, [])
        self.assertEqual(len(self.a.baseline["browser_extensions"]), 1)

    def test_firefox_corrupt_metadata_is_incomplete(self):
        p = self.home / ".mozilla/firefox/a.default-release/extensions.json"
        self.write(p, "not json")
        self.assertEqual(self.a._scan_firefox(), (0, True))

    def test_firefox_symlink_base_incomplete(self):
        p = self.home / ".mozilla/firefox"
        p.parent.mkdir(parents=True)
        p.symlink_to(self.folder)
        self.assertEqual(self.a._scan_firefox(), (0, True))

    def test_browser_enterprise_policy_reported_as_exposure(self):
        p = self.write(self.folder / "policy.json", json.dumps({"ExtensionInstallForcelist": ["example"]}))
        self.a._files = lambda bases, **_k: ([p], False) if any("policies" in str(x) for x in bases) else ([], False)
        self.a.browsers()
        self.assertIn("BROWSER_ENTERPRISE_POLICY", {x["rule"] for x in self.a.findings})
        self.assertEqual(self.a.coverage[-1]["check"], "browsers")

    def test_auth_bad_event_timestamps_never_count_as_good_telemetry(self):
        self.a.incident_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        now_us = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1_000_000)
        lines = [json.dumps({"MESSAGE":"Accepted publickey", "__REALTIME_TIMESTAMP":str(now_us)}),
                 json.dumps({"MESSAGE":"Accepted publickey", "__REALTIME_TIMESTAMP":"nonsense"}),
                 "not-json"]
        self.a.command = lambda *_a, **_k: {"status":"COMPLETED","stdout":"\n".join(lines), "exit":0}
        self.a.auth()
        stats = self.a.stats["auth"]
        self.assertEqual(stats["invalid_incident_timestamps"], 1)
        self.assertEqual(stats["malformed"], 1)
        self.assertEqual(stats["event_counts_0_to_72h_after_incident"].get("SSH_ACCEPTED"), 1)
        self.assertEqual(self.a.coverage[-1]["status"], "PARTIAL")

    def test_deep_package_drift_is_context_not_confirmed_compromise(self):
        self.a.profile = "deep"
        self.a._files = lambda *_a, **_k: ([], False)
        self.a.command = lambda *_a, **_k: {"status": "PARTIAL", "stdout": "??5?????? /usr/bin/example\n",
                                             "exit": 1, "error": "", "truncated": False}
        self.a.packages()
        self.assertIn("DPKG_FILE_DRIFT", {x["rule"] for x in self.a.findings})
        self.assertEqual(self.a.findings[-1]["kind"], "CONTEXT")
        # User scope cannot verify root-only files: reported as a scope limit.
        self.assertEqual(self.a.coverage[-1]["status"], "COMPLETED")
        self.assertIn("REQUIRES_SYSTEM_SCOPE", self.a.coverage[-1]["scope_limits"])

    def test_kernel_unavailable_secboot_indeterminate(self):
        self.a.kernel()
        self.assertIn("REQUIRES_SYSTEM_SCOPE", self.a.coverage[-1]["scope_limits"])
        self.assertNotIn("secure_boot_status", self.a.stats["kernel"])
        self.assertIn("kernel", self.a.stats)

if __name__ == "__main__":
    unittest.main()
