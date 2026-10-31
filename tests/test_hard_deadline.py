"""A-8: the whole-scan deadline is enforced, not merely cooperative.

A collector stuck in a blocking system call can never reach a budget check.
The hard deadline (SIGALRM after the budget plus a grace period) interrupts
it; the collector becomes FAILED/BUDGET_EXHAUSTED with its observations
discarded, the remaining collectors are SKIPPED, and the scan returns.
"""
from __future__ import annotations

import os
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import collectors, safety
from falsicore.collectors import Audit


def make_audit(home: Path) -> Audit:
    with patch("falsicore.collectors.os.geteuid", return_value=1001), \
         patch("falsicore.collectors.os.getuid", return_value=1001):
        audit = Audit("user", target_user="nobody", profile="quick")
    audit.home = home
    audit.uid = 1001
    return audit


class HardDeadline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        self.addCleanup(lambda: signal.setitimer(signal.ITIMER_REAL, 0))

    def blocking_audit(self, max_seconds: float):
        """An audit whose only collector blocks forever on a FIFO open."""
        audit = make_audit(self.home)
        fifo = self.home / "never-written"
        os.mkfifo(fifo)
        audit.max_seconds = max_seconds
        audit.profile_config["checks"] = ("blocker", "after")
        state = {"after_ran": False}

        def blocker() -> None:
            audit.finding("EXECUTABLE_IN_VOLATILE_PATH", "high", "would be discarded", "/tmp/x")
            fd = os.open(fifo, os.O_RDONLY)  # blocks until a writer appears; none ever does
            os.close(fd)
            audit.checked("blocker", "COMPLETED", "unreachable")

        def after() -> None:
            state["after_ran"] = True
            audit.checked("after", "COMPLETED", "ran")
        audit.blocker = blocker  # type: ignore[attr-defined]
        audit.after = after  # type: ignore[attr-defined]
        return audit, state

    def test_blocking_collector_is_interrupted_failed_and_rolled_back(self):
        audit, state = self.blocking_audit(max_seconds=0.3)
        with patch.object(collectors, "COLLECTOR_ORDER", ("blocker", "after")), \
             patch.object(collectors, "HARD_DEADLINE_MIN_GRACE_SECONDS", 0.2):
            started = time.monotonic()
            audit.scan()
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, "scan did not return promptly")
        rows = {c["check"]: c for c in audit.coverage}
        self.assertEqual(rows["blocker"]["status"], "FAILED")
        self.assertEqual(rows["blocker"]["reason_codes"], {"BUDGET_EXHAUSTED": 1})
        self.assertEqual(audit.findings, [], "observations of the interrupted collector must be discarded")
        self.assertEqual(rows["after"]["status"], "SKIPPED", "later collectors are skipped once the budget is gone")
        self.assertFalse(state["after_ran"])
        self.assertTrue(audit.hard_deadline_fired)
        self.assertTrue(audit.stats["runtime"]["hard_deadline_fired"])
        self.assertEqual(audit.stats["blocker_exception"], "DeadlineExpired")
        self.assertEqual(audit.stats["hard_deadline"]["armed"], True)

    def test_alarm_is_disarmed_and_handler_restored_after_scan(self):
        audit, _ = self.blocking_audit(max_seconds=0.3)
        with patch.object(collectors, "COLLECTOR_ORDER", ("blocker", "after")), \
             patch.object(collectors, "HARD_DEADLINE_MIN_GRACE_SECONDS", 0.2):
            audit.scan()
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_handler)

    def test_fast_scan_never_sees_the_alarm(self):
        audit = make_audit(self.home)
        audit.max_seconds = 5
        audit.profile_config["checks"] = ("quick_one",)
        audit.quick_one = lambda: audit.checked("quick_one", "COMPLETED", "fast")  # type: ignore[attr-defined]
        with patch.object(collectors, "COLLECTOR_ORDER", ("quick_one",)):
            audit.scan()
        self.assertFalse(audit.hard_deadline_fired)
        self.assertEqual(audit.coverage[0]["status"], "COMPLETED")
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_grace_period_keeps_cooperative_budget_first(self):
        audit = make_audit(self.home)
        audit.max_seconds = 100
        self.assertAlmostEqual(audit.hard_deadline_seconds(), 105.0)
        audit.max_seconds = 5
        self.assertAlmostEqual(audit.hard_deadline_seconds(), 7.0)

    def test_outside_main_thread_falls_back_to_cooperative_budget(self):
        audit = make_audit(self.home)
        result: dict[str, object] = {}

        def run() -> None:
            result["armed"] = audit._arm_hard_deadline(1.0)
            result["stats"] = dict(audit.stats.get("hard_deadline", {}))
        worker = threading.Thread(target=run)
        worker.start()
        worker.join(5)
        self.assertIsNone(result["armed"])
        self.assertEqual(result["stats"], {"armed": False, "reason": "NOT_MAIN_THREAD"})
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_handler)

    def test_alarm_between_collectors_only_sets_the_flag(self):
        """Outside a collector the handler must not raise: bookkeeping is never interrupted."""
        audit = make_audit(self.home)
        armed = audit._arm_hard_deadline(60)
        try:
            handler = signal.getsignal(signal.SIGALRM)
            self.assertFalse(audit._collector_active)
            handler(signal.SIGALRM, None)  # type: ignore[operator]
            self.assertTrue(audit.hard_deadline_fired)
            audit._collector_active = True
            with self.assertRaises(collectors.DeadlineExpired):
                handler(signal.SIGALRM, None)  # type: ignore[operator]
        finally:
            audit._collector_active = False
            audit._disarm_hard_deadline(armed)


class DeferredAlarm(unittest.TestCase):
    """The executor's cleanup section delays SIGALRM until it is complete."""

    def setUp(self):
        self.previous = signal.getsignal(signal.SIGALRM)
        self.addCleanup(lambda: signal.setitimer(signal.ITIMER_REAL, 0))
        self.addCleanup(lambda: signal.signal(signal.SIGALRM, self.previous))

    def test_alarm_is_delivered_after_the_section_not_inside(self):
        class Fired(Exception):
            pass

        def handler(_s, _f):
            raise Fired()
        signal.signal(signal.SIGALRM, handler)
        inside_completed = False
        with self.assertRaises(Fired):
            with safety.deferred_alarm():
                signal.setitimer(signal.ITIMER_REAL, 0.05)
                time.sleep(0.2)
                inside_completed = True
            time.sleep(0.2)  # the pending alarm lands here, once the mask is restored
        self.assertTrue(inside_completed)

    def test_probe_cleanup_runs_under_deferred_alarm(self):
        """An alarm during a probe interrupts the wait, yet the probe group is still reaped."""
        class Fired(Exception):
            pass

        def handler(_s, _f):
            raise Fired()
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 0.1)
        with self.assertRaises(Fired):
            safety._run_bounded("/bin/sleep", ["5"], timeout=5, limit=1024)
        # No child of ours may survive: the cleanup killed the group before the alarm surfaced.
        time.sleep(0.05)
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                with open(f"/proc/{entry.name}/stat", "rb") as f:
                    fields = f.read(4096).rsplit(b")", 1)[1].split()
                if int(fields[1]) == os.getpid() and fields[0] != b"Z":
                    cmd = Path(f"/proc/{entry.name}/cmdline").read_bytes()
                    self.assertNotIn(b"sleep", cmd, "orphaned probe survived the alarm")
            except (OSError, IndexError, ValueError):
                continue


if __name__ == "__main__":
    unittest.main()
