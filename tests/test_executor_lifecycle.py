"""Executor lifecycle contracts with disposable child processes only."""
from __future__ import annotations

import os
import signal
import sys
import time
import unittest
from unittest.mock import patch

from falsicore import safety


def run_py(script: str, timeout: float = 3, limit: int = 4096) -> dict:
    with patch.object(safety, "checked_executable", return_value=sys.executable):
        return safety.run_command("uname", ["-I", "-c", script], timeout=timeout, limit=limit)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); treat it as gone.
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except FileNotFoundError:
        return False


class ExecutorLifecycleTests(unittest.TestCase):
    def test_daemonized_grandchild_is_killed_after_successful_exit(self):
        # Grandchild detaches its stdio and outlives the parent inside our group.
        script = ("import os,sys,time\n"
                  "pid=os.fork()\n"
                  "if pid==0:\n"
                  "    fd=os.open(os.devnull,os.O_RDWR); os.dup2(fd,1); os.dup2(fd,2); time.sleep(30); os._exit(0)\n"
                  "sys.stdout.write(str(pid))\n")
        result = run_py(script)
        self.assertEqual(result["status"], "COMPLETED", result)
        self.assertTrue(result["residual_killed"])
        grandchild = int(result["stdout"])
        deadline = time.monotonic() + 2
        while alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(alive(grandchild), "residual group member survived a COMPLETED probe")

    def test_clean_exit_reports_no_residual(self):
        result = run_py("print('ok')")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["residual_killed"])

    def test_signal_death_is_labelled(self):
        result = run_py("import os,signal;os.kill(os.getpid(),signal.SIGSEGV)")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["exit"], -signal.SIGSEGV)
        self.assertEqual(result["error"], "signal:SIGSEGV")

    def test_stderr_is_separate_from_parsed_stdout(self):
        result = run_py("import sys;sys.stdout.write('data');sys.stderr.write('Hint: noise')")
        self.assertEqual(result["stdout"], "data")
        self.assertEqual(result["stderr"], "Hint: noise")

    def test_stderr_is_bounded_and_does_not_fail_probe(self):
        result = run_py("import sys;sys.stderr.write('e'*200000);sys.stdout.write('ok')")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(result["stderr"]), safety.MAX_DIAGNOSTIC_OUTPUT)
        self.assertEqual(result["stdout"], "ok")

    def test_leader_is_not_reaped_before_group_kill(self):
        calls = []
        real_killpg = os.killpg

        def spy(pgid, sig):
            # At killpg time the leader must still be our unreaped child.
            calls.append(os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None)
            return real_killpg(pgid, sig)
        with patch.object(safety.os, "killpg", side_effect=spy):
            run_py("print('x')")
        self.assertEqual(calls, [True])

    def test_escaped_pipe_holder_is_reported(self):
        script = ("import os,time\n"
                  "if os.fork()==0:\n"
                  "    os.setsid(); time.sleep(3); os._exit(0)\n"
                  "time.sleep(5)\n")
        result = run_py(script, timeout=0.4)
        self.assertEqual(result["status"], "FAILED")
        self.assertIn("timeout", result["error"])
        self.assertIn("PIPE_HOLDER_OUTSIDE_GROUP", result["error"])

    def test_self_test_transcript_merges_stderr(self):
        with patch.object(safety, "checked_executable", return_value=sys.executable):
            r = safety._run_bounded(sys.executable, ["-I", "-c", "import sys;sys.stderr.write('E')"], 3, 4096,
                                    merge_stderr=True)
        self.assertEqual(r["stdout"], "E")
        self.assertEqual(r["stderr"], "")


if __name__ == "__main__":
    unittest.main()
