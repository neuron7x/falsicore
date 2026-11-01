"""Boundary tests for collectors.py, written against the surviving-mutant profile.

The 0.1.3 baseline left most behavioural survivors in collectors.py on
counters (`denied`, `disappeared`, `unreadable`, `truncated`), caps (30
profiles, 150 listeners and module ids, 200 extensions, 24 start-up files) and
time windows (72 h). Each test pins one such boundary on a hermetic fixture
host (own root and /proc); nothing on the live machine is read.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import collectors
from falsicore.collectors import MAX_CMDLINE_BYTES, MAX_SHELL_FILES, Audit

UID = 24680
STAT_TAIL = ("S {ppid} 1 1 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 {start} 10000000 500 "
             "18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0")


def completed(stdout: str = "", status: str = "COMPLETED", exit_code: int | None = 0, stderr: str = "") -> dict:
    return {"status": status, "stdout": stdout, "stderr": stderr, "exit": exit_code, "elapsed_ms": 1,
            "truncated": False, "error": "", "residual_killed": False}


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.home = self.root / "home/fixture"
        self.home.mkdir(parents=True)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
        pw = SimpleNamespace(pw_uid=UID, pw_dir=str(self.home), pw_name="fixture")
        with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
             patch("falsicore.collectors.os.geteuid", return_value=UID), \
             patch("falsicore.collectors.os.getuid", return_value=UID):
            self.audit = Audit("user", target_user="fixture", profile="deep", root=self.root)
        self.outputs: dict[str, dict] = {}
        self.audit.command = self.fake_command

    def fake_command(self, tool, args, **kw):
        key = tool
        if tool == "journalctl":
            key = "journalctl:kernel" if "_TRANSPORT=kernel" in args else "journalctl:auth"
        return dict(self.outputs.get(key, completed("", "UNAVAILABLE", None)))

    def process(self, pid: int, exe: str | None, uid: int = UID, cmdline: list[str] | None = None,
                status_mode: int | None = None) -> Path:
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "status").write_text(f"Name:\tp\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t1\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (folder / "stat").write_text(f"{pid} (p) " + STAT_TAIL.format(ppid=1, start=1000 + pid) + "\n")
        if exe is not None:
            (folder / "exe").symlink_to(exe)
        argv = cmdline if cmdline is not None else [exe or "x"]
        (folder / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in argv))
        if status_mode is not None:
            (folder / "status").chmod(status_mode)
        return folder

    def row(self, check: str) -> dict:
        return next(c for c in self.audit.coverage if c["check"] == check)


class ProcessCounters(FixtureCase):
    def test_denied_vanished_and_foreign_are_counted_separately(self):
        self.process(100, "/usr/bin/a")
        self.process(101, "/usr/bin/b", status_mode=0)                     # status unreadable -> denied
        (self.proc / "102").mkdir()                                         # no status at all -> disappeared
        (self.proc / "102" / "stat").write_text("102 (p) " + STAT_TAIL.format(ppid=1, start=1) + "\n")
        foreign = self.process(103, "/usr/bin/c", uid=UID + 1)             # another account: exe readlink is EACCES on a live host
        protected = self.process(104, "/usr/bin/d")                         # own non-dumpable process: EACCES too
        self.process(105, None)                                             # exe link gone: the process vanished
        blocked = {os.stat(foreign).st_ino, os.stat(protected).st_ino}
        real_readlink = os.readlink

        def readlink(path, *args, dir_fd=None, **kwargs):
            if dir_fd is not None and os.fstat(dir_fd).st_ino in blocked and path == "exe":
                raise PermissionError(13, "Permission denied")
            return real_readlink(path, *args, dir_fd=dir_fd, **kwargs)
        with patch("falsicore.collectors.os.readlink", readlink):
            self.audit.processes()
        stats = self.audit.stats["processes"]
        self.assertEqual((stats["enumerated"], stats["denied"], stats["disappeared"]), (6, 1, 2))
        self.assertEqual((stats["other_accounts_not_visible"], stats["protected_own_processes"]), (1, 1))
        row = self.row("processes")
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(row["reason_codes"], {"PERMISSION_DENIED": 1})
        self.assertEqual(row["scope_limits"], {"OTHER_ACCOUNTS_NOT_VISIBLE": 1, "REQUIRES_SYSTEM_SCOPE": 1, "SOURCE_VANISHED": 2})

    def test_process_cap_is_exact(self):
        for pid in range(1, 8):
            self.process(pid, "/usr/bin/x")
        self.audit.profile_config["max_processes"] = 7
        self.audit.processes()
        self.assertEqual(self.row("processes")["status"], "COMPLETED")
        self.audit.coverage.clear()
        self.audit.profile_config["max_processes"] = 6
        self.audit.processes()
        self.assertEqual(self.row("processes")["reason_codes"], {"ENUMERATION_LIMIT": 1})
        self.assertEqual(self.audit.stats["processes"]["enumerated"], 6)

    def test_browser_cmdline_bound_is_exact(self):
        flag = "--no-sandbox"
        filler = "x" * (MAX_CMDLINE_BYTES - len("/opt/chrome/chrome\0") - len(flag + "\0") - 1)
        self.process(200, "/opt/chrome/chrome", cmdline=["/opt/chrome/chrome", filler, flag])
        self.audit.processes()
        self.assertEqual(self.audit.stats["processes"]["browser_cmdlines_truncated"], 0)
        self.assertIn("UNSAFE_BROWSER_LAUNCH_FLAG", {f["rule"] for f in self.audit.findings})
        self.audit.coverage.clear()
        self.audit.findings.clear()
        self.process(201, "/opt/chrome/chrome", cmdline=["/opt/chrome/chrome", filler + "yy", flag])
        self.audit.processes()
        self.assertEqual(self.audit.stats["processes"]["browser_cmdlines_truncated"], 1)
        self.assertEqual(self.row("processes")["reason_codes"], {"INPUT_TRUNCATED": 1})


class NetworkCaps(FixtureCase):
    def test_listener_cap_and_remote_access_ports(self):
        lines = [f"tcp LISTEN 0 128 0.0.0.0:{10000 + i} 0.0.0.0:* users:((\"d\",pid=1,fd=3))" for i in range(151)]
        lines.append('tcp LISTEN 0 128 0.0.0.0:5901 0.0.0.0:*')
        lines.append('tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*')
        self.outputs["ss"] = completed("\n".join(lines) + "\n")
        self.audit.network()
        stats = self.audit.stats["network"]
        self.assertEqual((len(stats["listeners"]), stats["listeners_truncated"]), (150, 2))
        self.assertEqual([f["evidence"]["port"] for f in self.audit.findings if f["rule"] == "REMOTE_ACCESS_PORT_EXPOSED"], ["5901"])
        self.assertEqual(stats["listeners_without_process_identity"], 2)
        self.assertEqual(self.row("network")["scope_limits"], {"OTHER_ACCOUNTS_NOT_VISIBLE": 2})

    def test_failed_ss_is_failed_not_partial(self):
        self.outputs["ss"] = completed("", "FAILED", 1)
        self.audit.network()
        self.assertEqual(self.row("network")["status"], "FAILED")
        self.audit.coverage.clear()
        self.outputs.pop("ss")
        self.audit.network()
        self.assertEqual(self.row("network")["status"], "UNAVAILABLE")


class TimeWindows(FixtureCase):
    def test_incident_window_boundaries(self):
        with patch("falsicore.collectors.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=UID, pw_dir=str(self.home), pw_name="fixture")), \
             patch("falsicore.collectors.os.geteuid", return_value=UID), patch("falsicore.collectors.os.getuid", return_value=UID):
            audit = Audit("user", target_user="fixture", root=self.root, incident_at="2026-10-01T00:00:00+00:00")
        incident = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
        target = self.home / "f"
        target.write_text("x")
        for delta, expected in ((72 * 3600, True), (72 * 3600 + 1, False), (-72 * 3600, True), (-72 * 3600 - 1, False)):
            when = (incident + dt.timedelta(seconds=delta)).timestamp()
            os.utime(target, (when, when))
            self.assertEqual(audit._mtime_near_incident(target), expected, delta)
        self.assertIsNone(self.audit._mtime_near_incident(target))     # no incident: None, not False
        base = int(incident.timestamp() * 1_000_000)
        lines = [json.dumps({"MESSAGE": "Accepted publickey for u", "__REALTIME_TIMESTAMP": str(base + offset)})
                 for offset in (-1, 0, 72 * 3600 * 1_000_000, 72 * 3600 * 1_000_000 + 1)]
        counters, within, n, malformed, bad = audit._journal_signals("\n".join(lines) + "\n")
        self.assertEqual((counters["SSH_ACCEPTED"], within["SSH_ACCEPTED"], n, malformed, bad), (4, 2, 4, 0, 0))
        _, _, _, malformed, bad = audit._journal_signals('{"MESSAGE": "x", "__REALTIME_TIMESTAMP": "0"}\nnot json\n')
        self.assertEqual((malformed, bad), (1, 1))

    def test_auth_event_limit_boundary_and_reader_group(self):
        limit = self.audit.profile_config["journal_lines"]
        entry = json.dumps({"MESSAGE": "pam_unix: session opened", "__REALTIME_TIMESTAMP": "1730000000000000"})
        self.outputs["journalctl:auth"] = completed((entry + "\n") * (limit - 1))
        with patch("falsicore.collectors._in_journal_reader_group", return_value=False):
            self.audit.auth()
        row = self.row("auth")
        self.assertEqual((row["status"], row["scope_limits"]), ("COMPLETED", {"OTHER_ACCOUNTS_NOT_VISIBLE": 1}))
        self.audit.coverage.clear()
        self.outputs["journalctl:auth"] = completed((entry + "\n") * limit)
        with patch("falsicore.collectors._in_journal_reader_group", return_value=True):
            self.audit.auth()
        row = self.row("auth")
        self.assertEqual((row["status"], row["reason_codes"], row["scope_limits"]), ("PARTIAL", {"INPUT_TRUNCATED": 1}, {}))
        self.audit.coverage.clear()
        self.outputs["journalctl:auth"] = completed("")
        with patch("falsicore.collectors._in_journal_reader_group", return_value=True):
            self.audit.auth()
        self.assertEqual(self.row("auth")["reason_codes"], {"HISTORY_UNAVAILABLE": 1})


class KernelAndBrowserCaps(FixtureCase):
    def test_module_id_cap(self):
        (self.proc / "modules").write_text("".join(f"m{i} 1 0 - Live 0x0\n" for i in range(151)))
        self.outputs["aa-status"] = completed("", "COMPLETED", 0)
        self.audit.kernel()
        stats = self.audit.stats["kernel"]
        self.assertEqual((stats["module_count"], len(stats["module_name_ids"])), (151, 150))
        self.assertEqual(self.row("kernel")["scope_limits"], {"REQUIRES_SYSTEM_SCOPE": 1})

    def test_profile_and_extension_caps(self):
        base = self.home / ".config/google-chrome"
        for i in range(31):
            manifest = base / f"Profile {i}" / "Extensions" / ("a" * 32) / "1.0_0" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"name": "n", "version": "1", "permissions": ["storage"]}))
        count, profiles, truncated = self.audit._scan_chromium("chrome", base)
        self.assertEqual((count, profiles, truncated), (30, 30, True))
        ext_root = self.home / ".config/chromium/Default/Extensions"
        for i in range(201):
            manifest = ext_root / f"{i:032d}" / "1.0_0" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"name": "n", "version": "1", "permissions": ["storage"]}))
        count, profiles, truncated = self.audit._scan_chromium("chromium", self.home / ".config/chromium")
        self.assertEqual((count, profiles, truncated), (200, 1, True))


class PersistenceCounters(FixtureCase):
    def write(self, relative: str, text: str, mode: int | None = None) -> Path:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if mode is not None:
            path.chmod(mode)
        return path

    def test_unreadable_files_are_counted_and_reported(self):
        self.write("/etc/systemd/system/a.service", "[Service]\nExecStart=/usr/bin/a\n", 0)
        self.write("/etc/cron.d/b", "* * * * * root /usr/bin/b\n", 0)
        (self.home / ".bashrc").write_text("export X=1\n")
        (self.home / ".bashrc").chmod(0)
        self.outputs["crontab"] = completed("", "FAILED", 1, "no crontab for fixture\n")
        self.audit.uid = os.getuid()      # the files are ours: unreadable is incompleteness, not another account
        self.audit.persistence()
        stats = self.audit.stats["persistence"]
        self.assertEqual(stats["unreadable"], 3)
        row = self.row("persistence")
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(row["reason_codes"].get("PERMISSION_DENIED"), 3)

    def test_crontab_failures_other_than_absence_are_tool_failures(self):
        self.outputs["crontab"] = completed("", "FAILED", 1, "crontab: permission denied\n")
        self.audit.persistence()
        self.assertIn("TOOL_FAILED", self.row("persistence")["reason_codes"])
        self.audit.coverage.clear()
        self.outputs["crontab"] = completed("", "FAILED", 1, "no crontab for fixture\n")
        self.audit.persistence()
        self.assertNotIn("TOOL_FAILED", self.row("persistence")["reason_codes"])

    def test_sourced_chain_stops_at_max_shell_files(self):
        self.outputs["crontab"] = completed("", "FAILED", 1, "no crontab for fixture\n")
        for i in range(MAX_SHELL_FILES + 5):
            (self.home / f".s{i}").write_text(f". ~/.s{i + 1}\n")
        (self.home / ".bashrc").write_text(". ~/.s0\n")
        self.audit.persistence()
        self.assertEqual(self.row("persistence")["reason_codes"].get("ENUMERATION_LIMIT"), 1)
        (self.home / f".s{MAX_SHELL_FILES + 5}").write_text("/tmp/.x\n")
        self.audit.coverage.clear()
        self.audit.findings.clear()
        self.audit.persistence()
        self.assertNotIn("SUSPICIOUS_SHELL_INIT", {f["rule"] for f in self.audit.findings}, "beyond the cap nothing is analysed")


class Construction(unittest.TestCase):
    def test_max_seconds_bounds_are_exact(self):
        pw = SimpleNamespace(pw_uid=UID, pw_dir="/nonexistent", pw_name="fixture")
        with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
             patch("falsicore.collectors.os.geteuid", return_value=UID), patch("falsicore.collectors.os.getuid", return_value=UID):
            self.assertEqual(Audit("user", target_user="fixture", max_seconds=5).max_seconds, 5)
            self.assertEqual(Audit("user", target_user="fixture", max_seconds=600).max_seconds, 600)
            for bad in (4, 601, 0):
                with self.assertRaises(ValueError, msg=bad):
                    Audit("user", target_user="fixture", max_seconds=bad)
            self.assertEqual(Audit("user", target_user="fixture", profile="quick").max_seconds, 35)
            with self.assertRaises(ValueError):
                Audit("user", target_user="fixture", incident_at="2026-10-01T00:00:00")   # no offset
            audit = Audit("user", target_user="fixture", incident_at="2026-10-01T02:00:00+02:00")
            self.assertEqual(audit.incident_at, dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc))


if __name__ == "__main__":
    unittest.main()
