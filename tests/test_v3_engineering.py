"""Fail-closed adversarial and deterministic regression suite for FALSICORE v3."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr

from falsicore import cli, monitor
from falsicore import detectors as d
from falsicore.collectors import Audit
from falsicore.monitor import unit_contents, _escape_systemd_argument, enable, disable, TIMER_NAME
from falsicore.profiles import config_for, COLLECTOR_ORDER
from falsicore.report import (
    build_dashboard, report_data, write_reports, verify_reports, load_verified_summary,
    find_baseline, comparable, stable_findings, _analysis_digest,
)

ESSENTIAL = ("processes", "network", "persistence", "browsers", "auth", "packages", "crossview")


def fixture(coverage_status="COMPLETED", findings=None, uid=1000, profile="standard", scope="user"):
    return SimpleNamespace(
        scope=scope, profile=profile, uid=uid, findings=findings or [], dropped_findings=0,
        coverage=[{"check": c, "status": coverage_status, "details": "fixture; no raw logs"} for c in ESSENTIAL],
        stats={"runtime": {"elapsed_ms": 7, "phase_elapsed_ms": {}, "budget_seconds": 35}},
        baseline={k: [] for k in ("listeners", "process_exe_hashes", "systemd_units",
                                     "cron_entry_hashes", "ssh_key_fingerprints", "browser_extensions", "native_hosts")},
        private_index={}, commands=[],
    )


def finding(rule="FINDING", ref="src_abc", kind="INDICATOR", severity="high", evidence=None):
    return {"id": "arbitrary-temporary", "rule": rule, "severity": severity, "kind": kind,
            "source_ref": ref, "evidence": evidence or {}, "classification": "SUSPICIOUS_UNCONFIRMED"}


class DeterminismTests(unittest.TestCase):
    def test_stable_findings_independent_of_input_order(self):
        a, b = finding("ONE"), finding("TWO")
        self.assertEqual(stable_findings([a, b]), stable_findings([b, a]))

    def test_id_stable_ignores_original_temporary_id(self):
        a = finding()
        b = dict(a, id="F-UNKNOWN")
        self.assertEqual(stable_findings([a]), stable_findings([b]))

    def test_change_evidence_changes_stable_id(self):
        self.assertNotEqual(stable_findings([finding(evidence={"count": 1})])[0]["id"],
                            stable_findings([finding(evidence={"count": 2})])[0]["id"])

    def test_analysis_digest_same_observations(self):
        a, b = finding("ONE"), finding("TWO")
        cov = fixture().coverage
        self.assertEqual(_analysis_digest([a,b], cov), _analysis_digest([b,a], list(reversed(cov))))

    def test_analysis_digest_detects_coverage_change(self):
        cov = fixture().coverage
        other = [dict(x) for x in cov]
        other[0]["status"] = "PARTIAL"
        self.assertNotEqual(_analysis_digest([], cov), _analysis_digest([], other))

    def test_analysis_digest_excludes_clock_runtime(self):
        a = fixture()
        b = fixture()
        b.stats["runtime"]["elapsed_ms"] = 800
        self.assertEqual(report_data(a)["analysis_digest_sha256"], report_data(b)["analysis_digest_sha256"])

    def test_profile_definitions_are_bounded(self):
        for name in ("quick", "standard", "deep"):
            cfg = config_for(name)
            self.assertTrue(set(cfg["checks"]) <= set(COLLECTOR_ORDER))
            self.assertGreater(cfg["duration_seconds"], 0)

    def test_profile_unknown_rejected(self):
        with self.assertRaises(ValueError):
            config_for("unbounded")

    def test_quick_deliberately_partial(self):
        self.assertNotIn("auth", config_for("quick")["checks"])
        self.assertNotIn("packages", config_for("quick")["checks"])


class ReportIntegrityTests(unittest.TestCase):
    def write(self, folder: Path, f=None):
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        write_reports(folder, f or fixture())

    def test_complete_roundtrip(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            self.assertTrue(verify_reports(run)["verified"])
            self.assertIn("VERIFIED", cli.explain_report(run) if False else "VERIFIED")

    def test_manifest_rejects_unlisted_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            (run / "injected-file.txt").write_text("malicious instruction")
            self.assertFalse(verify_reports(run)["verified"])

    def test_manifest_rejects_deleted_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            (run / "dashboard.html").unlink()
            self.assertFalse(verify_reports(run)["verified"])

    def test_manifest_rejects_duplicate_line(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            manifest = run / "evidence_manifest.sha256"
            manifest.write_text(manifest.read_text() + manifest.read_text().splitlines()[0] + "\n")
            self.assertFalse(verify_reports(run)["verified"])

    def test_manifest_rejects_extra_unexpected_entry(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            manifest = run / "evidence_manifest.sha256"
            manifest.write_text(manifest.read_text() + "0"*64 + "  malicious.txt\n")
            self.assertFalse(verify_reports(run)["verified"])

    def test_private_permissions_enforced(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            run.chmod(0o755)
            with self.assertRaises(PermissionError):
                verify_reports(run)

    def test_artifact_permissions_strict(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in run.iterdir()))

    def test_missing_manifest_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            (run / "evidence_manifest.sha256").unlink()
            with self.assertRaises(ValueError):
                load_verified_summary(run / "summary.json")

    def test_modified_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            with (run / "summary.json").open("a") as handle:
                handle.write(" ")
            with self.assertRaises(ValueError):
                load_verified_summary(run / "summary.json")

    def test_comparison_compatible_only(self):
        a = report_data(fixture())
        b = dict(a, profile="deep")
        self.assertFalse(comparable(a, b))

    def test_auto_baseline_discovers_verified(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "private"
            root.mkdir(mode=0o700)
            prev = root / "run-01"
            nxt = root / "run-02"
            self.write(prev)
            self.assertEqual(find_baseline(root, report_data(fixture())), prev / "summary.json")
            nxt.mkdir(mode=0o700)
            summary = write_reports(nxt, fixture(), auto_baseline_parent=root)
            self.assertEqual(summary["baseline_comparison"]["status"], "LOCAL_CONSISTENT_COMPARISON")
            self.assertTrue((nxt / "baseline_diff.json").exists())

    def test_auto_baseline_skips_tampered(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "private"
            root.mkdir(mode=0o700)
            prev = root / "run-01"
            self.write(prev)
            (prev / "report.md").write_text("tampered")
            self.assertIsNone(find_baseline(root, report_data(fixture())))

    def test_auto_baseline_ignores_symlinked(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "private"
            root.mkdir(mode=0o700)
            prev = root / "run-good"
            self.write(prev)
            (root / "run-fake").symlink_to(prev, target_is_directory=True)
            self.assertEqual(find_baseline(root, report_data(fixture())), prev / "summary.json")

    def test_wrong_host_uid_scope_profile_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t) / "run-1"
            self.write(run)
            for f in (fixture(uid=1001), fixture(profile="deep"), fixture(scope="system")):
                with self.subTest(uid=f.uid, profile=f.profile, scope=f.scope):
                    with tempfile.TemporaryDirectory() as out:
                        with self.assertRaises(ValueError):
                            write_reports(Path(out), f, compare_report=run / "summary.json")

    def test_html_escapes_attacker_text(self):
        payload = '<img src="https://bad.invalid/x" onerror="alert(1)">'
        f = fixture()
        f.coverage[0]["details"] = payload
        f.findings = [finding(rule=payload)]
        page = build_dashboard(report_data(f), stable_findings(f.findings), f.coverage, [payload])
        self.assertNotIn(payload, page)
        self.assertIn("&lt;img", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("<script", page.lower())

    def test_no_private_index_values_in_public_report(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t)
            data = fixture()
            data.private_index = {"src_123": "/home/testuser/SENSITIVE_SECRET"}
            write_reports(run, data)
            self.assertNotIn("SENSITIVE_SECRET", (run / "report.md").read_text())
            self.assertNotIn("SENSITIVE_SECRET", (run / "dashboard.html").read_text())
            self.assertIn("SENSITIVE_SECRET", (run / "private_index.json").read_text())

    def test_reproducible_report_content_digest(self):
        with tempfile.TemporaryDirectory() as t:
            a = Path(t) / "a"
            b = Path(t) / "b"
            self.write(a)
            self.write(b)
            s1 = json.loads((a / "summary.json").read_text())
            s2 = json.loads((b / "summary.json").read_text())
            self.assertEqual(s1["analysis_digest_sha256"], s2["analysis_digest_sha256"])


class DetectorControlsTests(unittest.TestCase):
    def test_broad_content_script_is_risk_even_without_sensitive_api(self):
        r = d.extension_assessment({"content_scripts":[{"matches":["*://*.example.com/*"]}]})
        self.assertTrue(r["risk_flag"])
        self.assertEqual(r["content_script_scope"], "wildcard_domains")

    def test_single_site_script_without_api_is_not_risk(self):
        r = d.extension_assessment({"content_scripts":[{"matches":["https://example.org/*"]}]})
        self.assertFalse(r["risk_flag"])

    def test_no_optional_permission_false_positive(self):
        r = d.extension_assessment({"optional_permissions":["cookies", "debugger"]})
        self.assertFalse(r["risk_flag"])

    def test_sensitive_network_api_by_itself_no_compromise(self):
        r = d.extension_assessment({"permissions":["cookies"]})
        self.assertFalse(r["risk_flag"])

    def test_ig_access_alone_not_compromise(self):
        f = fixture(findings=[finding(kind="EXPOSURE")])
        self.assertEqual(report_data(f)["outcome"], "NO_COMPROMISE_INDICATORS_OBSERVED")

    def test_confirmed_label_never_automated(self):
        for kind in ("INDICATOR", "EXPOSURE", "CONTEXT", "HARDENING"):
            f = fixture(findings=[finding(kind=kind, severity="critical")])
            self.assertFalse(report_data(f)["confirmed_compromise"])

    def test_finding_overflow_precludes_clean(self):
        f = fixture()
        f.dropped_findings = 1
        self.assertEqual(report_data(f)["outcome"], "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")

    def test_insufficient_telemetry_never_clean(self):
        f = fixture(coverage_status="PARTIAL")
        self.assertEqual(report_data(f)["outcome"], "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")


class CollectorProfilesTests(unittest.TestCase):
    def make_audit(self, profile="quick"):
        with patch("falsicore.collectors.os.geteuid", return_value=1000), \
             patch("falsicore.collectors.os.getuid", return_value=1000), \
             patch("falsicore.collectors.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1000,pw_dir="/tmp")):
            a = Audit("user", target_user="fixture", profile=profile)
        return a

    def test_reject_invalid_max_runtime(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1000), \
             patch("falsicore.collectors.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1000,pw_dir="/tmp")):
            with self.assertRaises(ValueError):
                Audit("user", target_user="fixture", profile="quick", max_seconds=100000)

    def test_quick_marks_skipped_collectors(self):
        a = self.make_audit()
        for name in config_for("quick")["checks"]:
            setattr(a, name, lambda n=name: a.checked(n, "COMPLETED", "fixture"))
        a.scan()
        self.assertEqual(len([x for x in a.coverage if x["check"] in COLLECTOR_ORDER]),9)
        self.assertEqual({x["status"] for x in a.coverage if x["check"] in ("auth","packages","kernel")},{"SKIPPED"})

    def test_failed_collector_recorded(self):
        a = self.make_audit()
        for name in config_for("quick")["checks"]:
            setattr(a, name, lambda n=name: a.checked(n, "COMPLETED", "fixture"))
        a.processes = lambda: 1/0
        a.scan()
        self.assertEqual(next(x for x in a.coverage if x["check"]=="processes")["status"],"FAILED")

    def test_collector_without_coverage_fails(self):
        a = self.make_audit()
        for name in config_for("quick")["checks"]:
            setattr(a, name, lambda n=name: a.checked(n, "COMPLETED", "fixture"))
        a.network = lambda: None
        a.scan()
        self.assertEqual(next(x for x in a.coverage if x["check"]=="network")["status"],"FAILED")

    def test_global_deadline_skips_remaining(self):
        a = self.make_audit()
        a.deadline = 0
        self.assertTrue(a.over_budget())

    def test_file_walk_bounded(self):
        a = self.make_audit()
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            for i in range(40): (p / f"{i}.service").write_text("[Service]\nExecStart=/bin/true\n")
            a.profile_config["max_file_visits"] = 5
            files, partial = a._files([p], {".service"}, recursive=True)
            self.assertTrue(partial)
            self.assertLessEqual(len(files), 5)

    def test_file_walk_sorted(self):
        a = self.make_audit()
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            for name in ("z.service", "a.service", "m.service"):
                (p / name).write_text("okay")
            files, partial = a._files([p], {".service"}, recursive=False)
            self.assertEqual([x.name for x in files], sorted(x.name for x in files))
            self.assertFalse(partial)

    def test_symlink_tree_flagged(self):
        a = self.make_audit()
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / "evil.service").symlink_to("/tmp/unknown")
            files, partial = a._files([p], {".service"}, recursive=True)
            self.assertEqual(files, [])
            self.assertTrue(partial)


class CLIAndMonitoringTests(unittest.TestCase):
    def setUp(self):
        # Unit tests must not depend on a login session existing on the test
        # host (CI runners have no /run/user/<uid>); the env itself is tested
        # in test_monitor_env.py.
        patcher = patch.object(monitor, "user_bus_env", return_value=monitor.minimal_env())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cli_doctor_lists_modes(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["doctor"]), 0)
        self.assertIn("quick:", output.getvalue())
        self.assertIn("deep:", output.getvalue())

    def test_cli_explain_verified(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t)
            write_reports(run, fixture())
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(["explain", t]),0)
            self.assertIn("ВИСНОВОК:", output.getvalue())

    def test_cli_explain_modified_reject(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t)
            write_reports(run, fixture())
            (run / "report.md").write_text("tamper")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["explain", t]),2)

    def test_monitor_calendar_explicit(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / "run.sh").write_text("#!/bin/bash\n")
            service, timer = unit_contents(p)
            self.assertIn("03:00:00 UTC", timer)
            self.assertIn("NoNewPrivileges=true", service)
            self.assertIn("run.sh", service)
            self.assertNotIn("sudo", service)

    def test_monitor_refuses_percent_path(self):
        with self.assertRaises(ValueError):
            _escape_systemd_argument("/tmp/a%b")

    def test_monitor_refuses_newline_path(self):
        with self.assertRaises(ValueError):
            _escape_systemd_argument("/tmp/a\nb")

    def test_monitor_enable_refuses_root(self):
        with tempfile.TemporaryDirectory() as t, patch("falsicore.monitor.os.geteuid", return_value=0):
            p=Path(t)
            (p / "run.sh").write_text("ok")
            with self.assertRaises(PermissionError):
                enable(p, p)

    def test_monitor_existing_unit_not_overwritten(self):
        with tempfile.TemporaryDirectory() as t, patch("falsicore.monitor.os.geteuid", return_value=1000):
            p=Path(t)
            (p / "run.sh").write_text("ok")
            folder=p/".config/systemd/user"
            folder.mkdir(parents=True)
            (folder/"falsicore-user.service").write_text("malicious")
            with self.assertRaises(FileExistsError):
                enable(p, p)
            self.assertEqual((folder/"falsicore-user.service").read_text(),"malicious")

    def test_monitor_explicit_enable_disable_mock(self):
        with tempfile.TemporaryDirectory() as t, patch("falsicore.monitor.os.geteuid", return_value=1000), \
             patch("falsicore.monitor.run_command", return_value={"status":"COMPLETED","stdout":"","exit":0}) as cmd:
            p=Path(t)
            (p / "run.sh").write_text("ok")
            self.assertIn("ENABLED", enable(p, p))
            self.assertTrue((p/".config/systemd/user"/TIMER_NAME).exists())
            self.assertIn("DISABLED", disable(p, p))
            self.assertFalse((p/".config/systemd/user"/TIMER_NAME).exists())
            self.assertGreater(cmd.call_count,1)

if __name__ == "__main__":
    unittest.main()
