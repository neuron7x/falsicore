"""Cross-view consistency: two kernel views of one fact must agree.

Fixtures replace the live probes (a /proc tree under the scan root, an
injectable PID existence oracle, canned ss output) so every branch is
deterministic. One live sanity test runs the real sweep against the real
/proc of this machine and must find nothing hidden.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import collectors
from falsicore.collectors import Audit

STAT_TAIL = ("S {ppid} 1 1 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 {start} 10000000 500 "
             "18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0")


class CrossViewFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.home = self.root / "home/u"
        self.home.mkdir(parents=True)
        self.proc = self.root / "proc"
        self.write("/proc/sys/kernel/pid_max", "4096\n")
        self.write("/proc/modules", "xt_conntrack 12288 1 - Live 0x0\n")
        self.write("/proc/self/mountinfo", "22 1 0:21 / /proc rw - proc proc rw\n"
                   "40 22 0:35 / /proc/sys/fs/binfmt_misc rw - autofs systemd-1 rw\n")
        for name in ("tcp", "tcp6", "udp", "udp6"):
            self.write(f"/proc/net/{name}", "  sl  local_address rem_address st\n")
        self.module_live("xt_conntrack")
        self.process(1, tgid=1)
        self.process(1200, tgid=1200, threads=(1201, 1202))
        self.exists: set[int] = {1, 1200, 1201, 1202}
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            self.audit = Audit("user", target_user="nobody", root=self.root)
        self.audit.home = self.home
        self.audit.uid = 1001
        self.audit.pid_probe = lambda pid: pid in self.exists
        self.ss_output = ""
        self.audit.command = lambda tool, args, **kw: {"status": "COMPLETED", "stdout": self.ss_output, "stderr": "",
                                                       "exit": 0, "elapsed_ms": 1, "truncated": False, "error": ""}

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def module_live(self, name: str) -> None:
        self.write(f"/sys/module/{name}/initstate", "live\n")

    def process(self, pid: int, tgid: int, threads: tuple[int, ...] = ()) -> None:
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "status").write_text(f"Name:\tp{pid}\nTgid:\t{tgid}\nPid:\t{pid}\nUid:\t1001\t1001\t1001\t1001\n")
        (folder / "stat").write_text(f"{pid} (p{pid}) " + STAT_TAIL.format(ppid=1, start=1000 + pid) + "\n")
        (folder / "task" / str(pid)).mkdir(parents=True, exist_ok=True)
        for tid in threads:
            (folder / "task" / str(tid)).mkdir(parents=True, exist_ok=True)

    def rules(self) -> list[str]:
        return sorted(f["rule"] for f in self.audit.findings)

    def row(self) -> dict:
        return next(c for c in self.audit.coverage if c["check"] == "crossview")

    def test_consistent_views_are_silent_and_complete(self):
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        self.assertEqual(self.rules(), [])
        self.assertEqual(self.row()["status"], "COMPLETED")
        stats = self.audit.stats["crossview"]
        self.assertEqual(stats["processes"]["threads"], 4)
        self.assertEqual(stats["processes"]["pid_max_probed"], 4096)

    def test_threads_are_not_hidden_processes(self):
        self.exists.add(1203)                      # a thread born after the listing: Tgid != pid
        self.process(1203, tgid=1200)
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        self.assertEqual(self.rules(), [])

    def test_process_known_to_kernel_but_unlisted_is_hidden(self):
        self.exists.add(3000)
        # /proc/3000 exists for a direct lookup (readdir hook only), but is not in the listing.
        self.process(3000, tgid=3000)
        (self.proc / "3000").rename(self.proc / ".3000")
        real_iterdir = Path.iterdir

        def listing_without_3000(path):
            for entry in real_iterdir(path):
                if entry.name == ".3000":
                    continue
                yield entry
        with patch.object(collectors, "PID_RECHECK_DELAY", 0), patch.object(Path, "iterdir", listing_without_3000):
            # lookup of /proc/3000 must still work: point the status read at the hidden copy
            original = self.audit._tgid_of
            self.audit._tgid_of = lambda pid: 3000 if pid == 3000 else original(pid)
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "HIDDEN_PROCESS"]
        self.assertEqual(finding["evidence"], {"how": "LISTING_HIDDEN"})
        self.assertEqual(finding["observations"][0]["pid"], 3000)
        self.assertEqual(finding["kind"], "INDICATOR")
        self.assertEqual(finding["severity"], "high")

    def test_process_hidden_from_lookup_too(self):
        self.exists.add(3500)                      # kill() says yes; /proc/3500 does not exist at all
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "HIDDEN_PROCESS"]
        self.assertEqual(finding["evidence"], {"how": "LOOKUP_AND_LISTING_HIDDEN"})

    def test_racing_process_that_appears_in_the_relisting_is_not_reported(self):
        self.exists.add(3600)
        state = {"calls": 0}
        original = self.audit._listed_pids_and_tids

        def listing():
            state["calls"] += 1
            listed, tids = original()
            if state["calls"] >= 2:
                listed = listed | {3600}          # it shows up on the confirming pass
            return listed, tids
        self.audit._listed_pids_and_tids = listing
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        self.assertEqual(self.rules(), [])

    def test_identical_hidden_processes_merge_into_one_finding(self):
        self.exists.update({3700, 3701})
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        hidden = [f for f in self.audit.findings if f["rule"] == "HIDDEN_PROCESS"]
        self.assertEqual(len(hidden), 1)
        self.assertEqual(sorted(o["pid"] for o in hidden[0]["observations"]), [3700, 3701])

    def test_live_module_missing_from_proc_modules_is_hidden(self):
        self.module_live("diamorphine")
        self.write("/sys/module/builtin_thing/parameters/x", "1\n")   # built-in: no initstate, never counted
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "HIDDEN_KERNEL_MODULE"]
        self.assertNotIn("diamorphine", str(finding["evidence"]))
        self.assertEqual(self.audit.stats["crossview"]["modules"], {"proc_modules": 1, "sysfs_live": 2, "hidden": 1})

    def test_listener_in_procfs_but_not_in_ss_is_hidden(self):
        self.write("/proc/net/tcp", "  sl  local_address rem_address st\n"
                   "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0\n"
                   "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1 0\n")
        self.ss_output = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n'
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "HIDDEN_LISTENER"]
        self.assertEqual(finding["evidence"], {"proto": "tcp", "port": 8080, "visible_in": "PROCFS_ONLY"})

    def test_listener_in_ss_but_not_in_procfs_is_hidden(self):
        self.ss_output = 'udp UNCONN 0 0 0.0.0.0:4444 0.0.0.0:*\n'
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "HIDDEN_LISTENER"]
        self.assertEqual(finding["evidence"], {"proto": "udp", "port": 4444, "visible_in": "NETLINK_ONLY"})

    def test_matching_listeners_are_silent(self):
        self.write("/proc/net/tcp6", "  sl  local_address rem_address st\n"
                   "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 1 1 0\n")
        self.ss_output = 'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=900,fd=4))\n'
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        self.assertEqual(self.rules(), [])

    def test_mount_over_proc_pid_is_reported(self):
        self.write("/proc/self/mountinfo", "22 1 0:21 / /proc rw - proc proc rw\n"
                   "90 22 0:50 / /proc/4242 rw - tmpfs tmpfs rw\n"
                   "91 22 0:51 / /proc/4243/status rw - tmpfs tmpfs rw\n")
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        [finding] = [f for f in self.audit.findings if f["rule"] == "PROC_PID_MOUNT_OVERLAY"]
        self.assertEqual(finding["evidence"], {"mount_count": 2})
        self.assertEqual(finding["observations"][0]["mount_points"], ["/proc/4242", "/proc/4243/status"])

    def test_budget_exhaustion_during_sweep_is_partial(self):
        self.write("/proc/sys/kernel/pid_max", "200000\n")
        self.audit.deadline = 0.0                  # already expired
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            self.audit.crossview()
        row = self.row()
        self.assertEqual(row["status"], "PARTIAL")
        self.assertIn("BUDGET_EXHAUSTED", row["reason_codes"])

    def test_pid_max_is_capped(self):
        self.write("/proc/sys/kernel/pid_max", "99999999\n")
        self.audit.deadline = None
        with patch.object(collectors, "PID_RECHECK_DELAY", 0), patch.object(collectors, "PID_SWEEP_MAX", 5000):
            self.audit.crossview()
        self.assertEqual(self.audit.stats["crossview"]["processes"]["pid_max_probed"], 5000)


class LiveCrossView(unittest.TestCase):
    """The real sweep on this machine: the kernel and /proc must agree about our own process."""

    def test_live_probe_semantics(self):
        self.assertTrue(collectors._live_pid_probe(os.getpid()))
        self.assertTrue(collectors._live_pid_probe(1))          # exists, not ours: EPERM
        self.assertFalse(collectors._live_pid_probe(2**22 - 1))  # near pid_max: almost surely free

    def test_live_mounts_and_listeners_are_readable_without_following_symlinks(self):
        """CV-1: /proc/self and /proc/net are symlinks; the no-follow reader must use /proc/<pid>."""
        with patch("falsicore.collectors.os.geteuid", return_value=os.getuid()), \
             patch("falsicore.collectors.os.getuid", return_value=os.getuid()):
            audit = Audit("user", target_user=os.environ.get("USER") or "nobody")
        audit.home = Path(tempfile.gettempdir())
        self.assertEqual(audit._proc_self(), Path("/proc") / str(os.getpid()))
        gaps, stats = collectors.Gaps(), {}
        audit._proc_mount_overlays(gaps, stats)
        self.assertIn("proc_pid_mounts", stats)
        self.assertIsNotNone(audit._procnet_listeners())
        self.assertEqual(dict(gaps.incomplete), {})
        self.assertEqual(dict(gaps.limits), {})

    def test_live_sweep_finds_nothing_hidden_on_this_host(self):
        with patch("falsicore.collectors.os.geteuid", return_value=os.getuid()), \
             patch("falsicore.collectors.os.getuid", return_value=os.getuid()):
            audit = Audit("user", target_user=os.environ.get("USER") or "nobody")
        audit.home = Path(tempfile.gettempdir())
        audit.command = lambda tool, args, **kw: {"status": "UNAVAILABLE", "stdout": "", "stderr": "", "exit": None,
                                                  "elapsed_ms": 0, "truncated": False, "error": "binary missing"}
        gaps, stats = collectors.Gaps(), {}
        audit._hidden_processes(gaps, stats)
        self.assertEqual(stats["processes"]["hidden"], 0, stats)
        self.assertGreaterEqual(stats["processes"]["listed"], 1)


if __name__ == "__main__":
    unittest.main()
