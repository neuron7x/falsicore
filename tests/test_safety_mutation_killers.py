"""Tests written to kill mutants that survived `tools/mutate.py --module safety`.

Executor bounds and states, probe environment and session, group-member
detection, private run directories and JSON serialisation.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import safety
from falsicore.safety import (MAX_COMMAND_OUTPUT, _group_has_live_members, _run_bounded, checked_executable,
                              create_run_directory, exclusive_write, run_command, utc_now, write_json)

PY = sys.executable


class ExecutorBounds(unittest.TestCase):
    def test_argument_bounds_are_exact(self):                          # safety:115
        for timeout, limit in ((0, 10), (181, 10), (1, -1), (1, MAX_COMMAND_OUTPUT + 1)):
            with self.assertRaises(ValueError, msg=(timeout, limit)):
                _run_bounded("/bin/true", [], timeout=timeout, limit=limit)
        self.assertEqual(_run_bounded(PY, ["-c", "pass"], timeout=180, limit=MAX_COMMAND_OUTPUT)["status"], "COMPLETED")
        zero = _run_bounded(PY, ["-c", "print('x')"], timeout=5, limit=0)
        self.assertEqual((zero["status"], zero["truncated"], zero["stdout"]), ("PARTIAL", True, ""))

    def test_output_limit_boundary(self):                              # safety:157/159/170
        exact = _run_bounded(PY, ["-c", "import sys; sys.stdout.write('a' * 100)"], timeout=5, limit=100)
        self.assertEqual((exact["status"], exact["truncated"], len(exact["stdout"])), ("COMPLETED", False, 100))
        over = _run_bounded(PY, ["-c", "import sys; sys.stdout.write('a' * 101)"], timeout=5, limit=100)
        self.assertEqual((over["status"], over["truncated"], len(over["stdout"])), ("PARTIAL", True, 100))
        big = _run_bounded(PY, ["-c", "import sys; sys.stdout.write('b' * 200000)"], timeout=10, limit=300000)
        self.assertEqual((big["status"], len(big["stdout"])), ("COMPLETED", 200000))

    def test_stderr_is_bounded_separately(self):                       # safety:166/168
        r = _run_bounded(PY, ["-c", "import sys; sys.stderr.write('e' * 70000); sys.stdout.write('ok')"], timeout=10, limit=1024)
        self.assertEqual((r["status"], r["stdout"]), ("COMPLETED", "ok"))
        self.assertEqual(len(r["stderr"]), safety.MAX_DIAGNOSTIC_OUTPUT)

    def test_exit_codes_and_signal_labels(self):                       # safety:184/209/211
        self.assertEqual(_run_bounded(PY, ["-c", "raise SystemExit(3)"], timeout=5, limit=1024)["exit"], 3)
        ok = _run_bounded(PY, ["-c", "pass"], timeout=5, limit=1024)
        self.assertEqual((ok["exit"], ok["error"]), (0, ""))
        killed = _run_bounded(PY, ["-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"], timeout=5, limit=1024)
        self.assertEqual((killed["status"], killed["exit"], killed["error"]), ("FAILED", -15, "signal:SIGTERM"))
        closed = _run_bounded(PY, ["-c", "import os, sys, time; os.close(1); os.close(2); time.sleep(0.2); sys.exit(3)"],
                              timeout=5, limit=1024)
        self.assertEqual((closed["status"], closed["exit"]), ("FAILED", 3))

    def test_missing_binary_is_failed_with_the_exception_name(self):    # safety:189
        r = _run_bounded("/nonexistent/falsicore-probe", [], timeout=5, limit=1024)
        self.assertEqual((r["status"], r["error"], r["exit"]), ("FAILED", "FileNotFoundError", None))

    def test_probe_runs_in_its_own_session_with_the_given_environment(self):   # safety:131/132
        # The interpreter may add LC_CTYPE (locale coercion), so only our variables are asserted.
        code = ("import os, sys; sys.stdout.write(f\"{os.getsid(0) != os.getsid(os.getppid())} "
                "{os.environ.get('FALSICORE_T', '-')} {os.environ.get('PATH', '-')} {os.environ.get('TZ', '-')}\")")
        own = _run_bounded(PY, ["-c", code], timeout=5, limit=1024, env={"FALSICORE_T": "x", "PATH": "/usr/bin:/bin"})
        self.assertEqual(own["stdout"], "True x /usr/bin:/bin -")
        minimal = _run_bounded(PY, ["-c", code], timeout=5, limit=1024)
        self.assertEqual(minimal["stdout"], "True - /usr/bin:/usr/sbin:/bin:/sbin UTC")
        self.assertEqual(sorted(safety.minimal_env()), ["LANG", "LC_ALL", "PATH", "TZ"])

    def test_unavailable_tool_record(self):                            # safety:82/83
        with patch.object(safety, "TRUSTED_BIN_DIRS", ("/nonexistent",)):
            r = run_command("ss", ["-H", "-tuna", "-p"])
        self.assertEqual(r, {"status": "UNAVAILABLE", "stdout": "", "stderr": "", "exit": None, "elapsed_ms": 0,
                             "truncated": False, "error": "binary missing", "residual_killed": False})

    def test_checked_executable_requires_a_regular_executable_file(self):   # safety:60 and->or
        with tempfile.TemporaryDirectory() as td:
            plain = Path(td) / "ss"
            plain.write_text("#!/bin/sh\n")
            plain.chmod(0o600)
            with patch.object(safety, "TRUSTED_BIN_DIRS", (td,)):
                self.assertIsNone(checked_executable("ss"))
                plain.chmod(0o700)
                self.assertEqual(checked_executable("ss"), str(plain))
                (Path(td) / "ip").mkdir()
                (Path(td) / "ip").chmod(0o700)
                self.assertIsNone(checked_executable("ip"))             # a directory is executable but not a file
        with self.assertRaises(ValueError):
            checked_executable("bash")

    def test_utc_now_format(self):                                     # safety:32
        self.assertRegex(utc_now(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")


class GroupMembers(unittest.TestCase):
    def test_live_members_of_a_probe_group(self):                       # safety:241-253
        import signal
        import time
        # A leader in its own session with one grandchild: the leader itself never counts.
        leader = subprocess.Popen([PY, "-c", "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', "
                                   "'import time; time.sleep(5)']); time.sleep(5)"], start_new_session=True)
        try:
            deadline = time.monotonic() + 3
            while not _group_has_live_members(leader.pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(_group_has_live_members(leader.pid))
            self.assertFalse(_group_has_live_members(2**22 - 1))
        finally:
            os.killpg(leader.pid, signal.SIGKILL)
            leader.wait()
        deadline = time.monotonic() + 3
        while _group_has_live_members(leader.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(_group_has_live_members(leader.pid), "killed members are zombies or gone, never live")


class PrivateRunDirectory(unittest.TestCase):
    def test_umask_and_modes(self):                                    # safety:323/332/337
        previous = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as td:
                parent = Path(td) / "runs"
                run = create_run_directory(parent)
                self.assertEqual(os.umask(0o077), 0o077, "scan umask is set process-wide")
                self.assertEqual(oct(parent.stat().st_mode & 0o777), "0o700")
                self.assertEqual(oct(run.stat().st_mode & 0o777), "0o700")
                self.assertTrue(run.name.startswith("run-"))
        finally:
            os.umask(previous)

    def test_insufficient_disk_space_is_refused(self):                 # safety:334
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / "runs"
            usage = os.statvfs(td)
            fake = type("U", (), {"free": 32 * 1024 * 1024 - 1, "total": 1, "used": 1})()
            with patch("falsicore.safety.shutil.disk_usage", return_value=fake):
                with self.assertRaises(OSError):
                    create_run_directory(parent)
            self.assertIsNotNone(usage)
            fake.free = 32 * 1024 * 1024
            with patch("falsicore.safety.shutil.disk_usage", return_value=fake):
                create_run_directory(parent)

    def test_write_json_is_sorted_indented_and_keeps_unicode(self):    # safety:361
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.json"
            write_json(path, {"b": "є", "a": [1, 2]})
            self.assertEqual(path.read_text(), '{\n  "a": [\n    1,\n    2\n  ],\n  "b": "є"\n}\n')
            self.assertEqual(json.loads(path.read_text()), {"a": [1, 2], "b": "є"})
            with self.assertRaises(FileExistsError):
                exclusive_write(path, "again")

    def test_version_label_is_a_string(self):                          # safety:260
        self.assertEqual(safety._signal_name(15), "SIGTERM")
        self.assertEqual(safety._signal_name(200), "200")
        self.assertTrue(re.fullmatch(r"\d{4}-.*", utc_now()))


if __name__ == "__main__":
    unittest.main()
