"""Mutation-targeted security contracts for bounded offline and live collectors.

No privileged operations or host mutation. All filesystem inputs are fixtures.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from falsicore import collectors, detectors
from falsicore.collectors import Audit, Gaps


class SourceReferenceBounds(unittest.TestCase):
    def test_dpkg_resource_budget_is_exactly_the_stated_contract(self):
        self.assertEqual(collectors.DPKG_DB_MAX_RECORDS, 20_000)
        self.assertEqual(collectors.DPKG_DB_MAX_BYTES, 128 * 1024 * 1024)

    def test_absolute_attested_name_must_be_canonical(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "usr/bin/dircolors"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"safe fixture\n")
            audit = Audit.__new__(Audit)
            audit.root = root
            audit.package_attested = lambda *args: True
            self.assertIsNone(audit._attested_program("/usr/bin/./dircolors"))
            self.assertIsNone(audit._attested_program("/usr//bin/dircolors"))
            self.assertEqual(audit._attested_program("/usr/bin/dircolors"),
                             binary)

    def test_absent_eval_site_counter_never_infers_trust(self):
        audit = Audit.__new__(Audit)
        audit.stats = {}
        audit._attested_program = lambda name: Path("/usr/bin/dircolors")
        audit.source = lambda path: "fixture-id"
        analysis = {"limitations": ["EXPANSION_NOT_RESOLVED"],
                    "qualified_eval_sites": ["dircolors"],
                    "unresolved_expansions": 1}
        gaps = Gaps()
        audit._shell_limit(analysis, "synthetic-source", None, gaps)
        self.assertEqual(gaps.incomplete["PARSE_UNSUPPORTED"], 1)
        self.assertNotIn("EVAL_OF_ATTESTED_PROGRAM_OUTPUT", gaps.limits)


class ProcMountVisibility(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.proc = self.root / "proc"
        self.mount = self.proc / "self/mountinfo"
        self.mount.parent.mkdir(parents=True)
        pid_max = self.proc / "sys/kernel/pid_max"
        pid_max.parent.mkdir(parents=True)
        pid_max.write_text("1\n")
        self.audit = Audit.__new__(Audit)
        self.audit.scope = "user"
        self.audit.uid = 1001
        self.audit.proc_root = self.proc
        self.audit._proc_self = lambda: self.proc / "self"
        self.audit._listed_pids_and_tids = lambda: (set(), set())
        self.audit.pid_probe = lambda pid: False
        self.audit.over_budget = lambda: False
        self.audit.boot_id = "fixture"
        self.audit.findings = []
        self.audit.stats = {}

    def measure(self):
        gaps, stats = Gaps(), {}
        self.audit._hidden_processes(gaps, stats)
        return gaps, stats

    def test_hidepid_is_a_scope_limit_with_zero_claimed_hidden_pids(self):
        self.mount.write_text("22 1 0:21 / /proc rw,hidepid=2 - proc proc rw\n")
        gaps, stats = self.measure()
        self.assertEqual(gaps.limits["OTHER_ACCOUNTS_NOT_VISIBLE"], 1)
        self.assertEqual(stats["processes"], {
            "status": "HIDEPID_RESTRICTED", "hidden": 0, "pid_max_probed": 0})

    def test_mountinfo_five_field_boundary_is_not_indexed_as_six_fields(self):
        self.mount.write_text("22 1 0:21 / /proc\n")
        gaps, stats = self.measure()
        self.assertEqual(dict(gaps.incomplete), {})
        self.assertEqual(stats["processes"]["pid_max_probed"], 1)

    def test_truncated_mountinfo_prevents_untrusted_pid_negative_inference(self):
        self.mount.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        gaps, stats = self.measure()
        self.assertEqual(gaps.incomplete["INPUT_TRUNCATED"], 1)
        self.assertEqual(stats["processes"]["status"],
                         "MOUNT_VISIBILITY_UNAVAILABLE")
        self.assertEqual(stats["processes"]["pid_max_probed"], 0)

    def test_missing_mount_policy_is_explicitly_incomplete(self):
        gaps, stats = self.measure()
        self.assertEqual(gaps.incomplete["READ_FAILED"], 1)
        self.assertEqual(stats["processes"]["status"],
                         "MOUNT_VISIBILITY_UNAVAILABLE")


class SocketTableBounds(unittest.TestCase):
    def test_blank_untrusted_ss_rows_do_not_crash_parser(self):
        self.assertEqual(collectors._ss_listener_endpoints("\n\n"), set())
        self.assertEqual(collectors._ss_listener_endpoints(
            "\n tcp LISTEN 0 0 127.0.0.1:22\n"),
            {("tcp4", "127.0.0.1", 22)})

    @staticmethod
    def audit(probes, outputs, calls, findings):
        a = Audit.__new__(Audit)
        a._procnet_listeners = lambda: probes.pop(0)

        def command(name, args, **kwargs):
            calls.append((name, args, kwargs))
            return {"status": "COMPLETED", "stdout": outputs.pop(0),
                    "truncated": False}

        a.command = command
        a._listener_evidence = lambda endpoint, view: {
            "endpoint": endpoint, "view": view}
        a.finding = lambda *args, **kwargs: findings.append((args, kwargs))
        return a

    def test_procfs_findings_are_capped_at_fifty(self):
        stable = {("tcp4", "127.0.0.1", port)
                  for port in range(11000, 11051)}
        calls, findings = [], []
        audit = self.audit([stable, stable], [""], calls, findings)
        gaps, stats = Gaps(), {}
        audit._hidden_listeners(gaps, stats)
        self.assertEqual(len(findings), 50)
        self.assertEqual(stats["listeners"]["procfs_only"], 51)
        self.assertEqual(dict(gaps.incomplete), {})

    def test_confirmed_netlink_only_findings_are_capped_and_timeout_bounded(self):
        line = "".join(f"udp UNCONN 0 0 127.0.0.1:{port}\n"
                       for port in range(11000, 11051))
        calls, findings = [], []
        audit = self.audit([set(), set(), set()],
                           [line, line], calls, findings)
        gaps, stats = Gaps(), {}
        audit._hidden_listeners(gaps, stats)
        self.assertEqual(len(findings), 50)
        self.assertEqual(stats["listeners"]["netlink_only"], 51)
        self.assertEqual([c[2]["timeout"] for c in calls], [15, 15])
        self.assertEqual(dict(gaps.incomplete), {})


class OfflineVerdictGate(unittest.TestCase):
    def test_skipped_live_views_must_have_explicit_reason_codes(self):
        coverage = []
        for check in ("processes", "network", "persistence", "browsers",
                      "auth", "packages", "crossview"):
            skip = check in {"processes", "network", "crossview"}
            coverage.append({
                "check": check, "status": "SKIPPED" if skip else "COMPLETED",
                "reason_codes": {"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1} if skip else {},
                "scope_limits": {}})
        self.assertEqual(detectors.interpret_verdict([], coverage),
                         "NO_COMPROMISE_INDICATORS_OBSERVED")


if __name__ == "__main__":
    unittest.main()
