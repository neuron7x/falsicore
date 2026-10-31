"""Synthetic endpoint fixtures for Linux telemetry; no real attacker code is used."""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import detectors
from falsicore.collectors import Audit


def make_audit(home: Path, *, profile="standard", incident_at=None) -> Audit:
    with patch("falsicore.collectors.os.geteuid", return_value=1001), \
         patch("falsicore.collectors.os.getuid", return_value=1001):
        audit = Audit("user", target_user="nobody", profile=profile, incident_at=incident_at)
    audit.home = home
    return audit


class ProcessAndNetworkFixtures(unittest.TestCase):
    def test_proc_snapshot_classifies_volatile_root_and_browser_flags(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            proc = root / "proc"
            proc.mkdir()
            for pid, uid, executable, command in (
                    ("210", 0, "/tmp/mystery", b"mystery\0"),
                    ("211", 1001, "/usr/bin/brave-browser", b"brave\0--no-sandbox\0")):
                p = proc / pid
                p.mkdir()
                (p / "status").write_text(f"Name:\ttest\nUid:\t{uid} {uid} {uid} {uid}\nPPid:\t1\n")
                (p / "exe").symlink_to(executable)
                (p / "cmdline").write_bytes(command)
            audit = make_audit(root)
            audit.proc_root = proc
            audit.processes()
            self.assertEqual(audit.coverage[-1]["status"], "COMPLETED")
            rules = [x["rule"] for x in audit.findings]
            self.assertIn("EXECUTABLE_IN_VOLATILE_PATH", rules)
            self.assertIn("UNSAFE_BROWSER_LAUNCH_FLAG", rules)
            self.assertIn(210, audit.suspicious_exec_pids)
            self.assertEqual(audit.stats["processes"]["browser_processes"], 1)

    def test_snapshot_correlates_public_egress_and_exposed_listener(self):
        with tempfile.TemporaryDirectory() as td:
            audit = make_audit(Path(td))
            audit.suspicious_exec_pids.add(210)
            ss = ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\\\"sshd\\\",pid=998,fd=3))\n"
                  "tcp ESTAB 0 0 192.0.2.2:50222 1.1.1.1:443 users:((\\\"app\\\",pid=210,fd=4))\n")
            audit.command = lambda *a, **k: {"status": "COMPLETED", "stdout": ss, "exit": 0, "truncated": False}
            audit.network()
            rules = [f["rule"] for f in audit.findings]
            self.assertIn("REMOTE_ACCESS_PORT_EXPOSED", rules)
            self.assertIn("TEMP_PROCESS_PUBLIC_EGRESS", rules)
            self.assertEqual(audit.stats["network"]["socket_count"], 2)
            self.assertIn("tcp/22/wildcard", audit.baseline["listeners"])

    def test_missing_process_identity_is_reported_as_partial(self):
        with tempfile.TemporaryDirectory() as td:
            audit = make_audit(Path(td))
            ss = "tcp LISTEN 0 128 *:3389 *:*\n"
            audit.command = lambda *a, **k: {"status": "COMPLETED", "stdout": ss, "exit": 0}
            audit.network()
            self.assertIn("OTHER_ACCOUNTS_NOT_VISIBLE", audit.coverage[-1]["scope_limits"])
            self.assertEqual(audit.stats["network"]["listeners_without_process_identity"], 1)


class BrowserFixtures(unittest.TestCase):
    def test_chromium_risky_vs_benign_extension_assessment(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            versions = [
                ("extensionbenign", "2.0", {"manifest_version": 3, "name": "quiet", "permissions": []}),
                ("extensionpower", "10.0", {"manifest_version": 3, "permissions": ["cookies"], "host_permissions": ["https://*.instagram.com/*"]}),
            ]
            for extid, version, obj in versions:
                folder = base / "Default" / "Extensions" / extid / version
                folder.mkdir(parents=True)
                (folder / "manifest.json").write_text(json.dumps(obj))
            audit = make_audit(base)
            count, profiles, partial = audit._scan_chromium("brave", base)
            self.assertEqual((count, profiles, partial), (2,1,False))
            self.assertEqual(len(audit.baseline["browser_extensions"]), 2)
            self.assertEqual([f["rule"] for f in audit.findings], ["POWERFUL_BROWSER_EXTENSION"])

    def test_broken_browser_manifest_is_flagged_for_review(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            folder = base / "Default/Extensions/id/1.0"
            folder.mkdir(parents=True)
            (folder / "manifest.json").write_text("this isn't JSON")
            audit = make_audit(base)
            total, profiles, partial = audit._scan_chromium("chromium", base)
            self.assertEqual((total, profiles), (0,1))
            self.assertEqual([x["rule"] for x in audit.findings], ["INVALID_EXTENSION_MANIFEST"])


    def test_symlinked_chromium_extensions_mark_gap(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            profile = base / "Default"
            profile.mkdir()
            (profile / "Extensions").symlink_to(base)
            audit = make_audit(base)
            self.assertEqual(audit._scan_chromium("chromium", base), (0,1,True))

    def test_symlinked_firefox_profile_marks_gap(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "proxy.default-release").symlink_to(base)
            audit = make_audit(base)
            self.assertEqual(audit._scan_firefox(base), (0,True))

    def test_empty_chromium_version_directory_marks_gap(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "Default/Extensions/extension-without-version").mkdir(parents=True)
            audit = make_audit(base)
            self.assertEqual(audit._scan_chromium("chromium", base), (0,1,True))

    def test_firefox_disabled_high_permission_addon_not_called_active(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            profile = base / "abcd.default-release"
            profile.mkdir()
            addons = [
                {"id": "disabled@ext", "type": "extension", "active": False,
                 "userPermissions": {"permissions": ["cookies"], "origins": ["https://instagram.com/*"]}},
                {"id": "active@ext", "type": "extension", "active": True,
                 "userPermissions": {"permissions": ["cookies"], "origins": ["https://instagram.com/*"]}},
            ]
            (profile / "extensions.json").write_text(json.dumps({"addons": addons}))
            audit = make_audit(base)
            total, partial = audit._scan_firefox(base, "firefox")
            self.assertEqual((total, partial), (2,False))
            self.assertEqual([f["rule"] for f in audit.findings], ["POWERFUL_FIREFOX_EXTENSION"])

    def test_firefox_malformed_metadata_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            profile = base / "abcd.default-release"
            profile.mkdir()
            (profile / "extensions.json").write_text("[]notjson")
            audit = make_audit(base)
            self.assertEqual(audit._scan_firefox(base), (0,True))


class JournalAndPackageFixtures(unittest.TestCase):
    def test_auth_incident_window_and_malformed_timestamps_are_visible(self):
        with tempfile.TemporaryDirectory() as td:
            anchor = dt.datetime(2026,10,25,12, tzinfo=dt.timezone.utc)
            audit = make_audit(Path(td), incident_at=anchor.isoformat())
            soon = int((anchor + dt.timedelta(hours=4)).timestamp()*1_000_000)
            lines = [
                json.dumps({"MESSAGE": "sshd[12]: Accepted publickey for user", "__REALTIME_TIMESTAMP": str(soon)}),
                json.dumps({"MESSAGE": "sshd[12]: Failed password for user", "__REALTIME_TIMESTAMP": "invalid"}),
                "not-json",
            ]
            audit.command = lambda *a, **k: {"status": "COMPLETED", "stdout": "\n".join(lines), "exit": 0}
            audit.auth()
            self.assertEqual(audit.coverage[-1]["status"], "PARTIAL")
            data = audit.stats["auth"]
            self.assertEqual(data["event_counts"]["SSH_ACCEPTED"], 1)
            self.assertEqual(data["malformed"], 1)
            self.assertEqual(data["invalid_incident_timestamps"], 1)
            self.assertEqual(data["event_counts_0_to_72h_after_incident"], {"SSH_ACCEPTED": 1})
            self.assertIn("REMOTE_AUTHENTICATION_REVIEW", {f["rule"] for f in audit.findings})

    def test_apt_insecure_source_and_dpkg_drift_are_distinguished(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "malconfigured.sources"
            path.write_text("Types: deb\nAllow-Insecure: yes\n")
            audit = make_audit(Path(td), profile="deep")
            audit._files = lambda *a, **kw: ([path], False)
            audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "??5?????? c /etc/example.conf\n"
                                                                            "????????? /usr/lib/root-only\n",
                                                  "exit": 1, "truncated": False, "error": ""}
            audit.packages()
            self.assertIn("REQUIRES_SYSTEM_SCOPE", audit.coverage[-1]["scope_limits"])
            self.assertEqual(audit.stats["repos"]["insecure_source_files"], 1)
            self.assertIn("INSECURE_PACKAGE_SOURCE_SETTING", {f["rule"] for f in audit.findings})
            # A changed conffile is context; the unreadable file is a user-scope limit.
            self.assertIn("PACKAGE_CONFFILE_CHANGED", {f["rule"] for f in audit.findings})
            self.assertNotIn("PACKAGE_FILE_DRIFT", {f["rule"] for f in audit.findings})

    def test_absent_journal_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            audit = make_audit(Path(td))
            audit.command = lambda *a, **k: {"status": "UNAVAILABLE", "stdout": "", "exit": None}
            audit.auth()
            self.assertEqual(audit.coverage[-1]["status"], "UNAVAILABLE")
            self.assertEqual(audit.findings, [])


if __name__ == "__main__":
    unittest.main()
