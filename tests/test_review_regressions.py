"""Regression tests for defects found by the independent A/B/C reviews (0.1.3).

Disposable processes and synthetic fixtures only; the operator's real browser,
shell and service configuration are never modified.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import cli, collectors, detectors, guide, report
from falsicore.collectors import Audit, Gaps

ROOT = Path(__file__).resolve().parents[1]


def make_audit(home: Path, profile: str = "standard") -> Audit:
    with patch("falsicore.collectors.os.geteuid", return_value=1001), \
         patch("falsicore.collectors.os.getuid", return_value=1001):
        audit = Audit("user", target_user="nobody", profile=profile)
    audit.home = home
    audit.uid = 1001
    return audit


class LiveProcessAttribution(unittest.TestCase):
    """B-1: attribution is captured at observation time from a pinned /proc dirfd."""

    def setUp(self):
        # A disposable copy of sleep under /tmp is exactly what the volatile-path rule targets.
        self.dir = tempfile.mkdtemp(prefix="fc-attr-", dir="/tmp")
        self.exe = Path(self.dir) / "sleeper"
        shutil.copy2(shutil.which("sleep"), self.exe)
        self.proc = subprocess.Popen([str(self.exe), "30"])
        self.addCleanup(self._cleanup)
        time.sleep(0.05)

    def _cleanup(self):
        self.proc.kill()
        self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _finding(self, audit):
        audit.processes()
        for f in audit.findings:
            for o in f.get("observations", []):
                if o.get("pid") == self.proc.pid:
                    return f, o
        self.fail("disposable /tmp process not reported")

    def test_identity_survives_process_exit(self):
        audit = Audit("user")
        finding, obs = self._finding(audit)
        self.assertEqual(finding["rule"], "EXECUTABLE_IN_VOLATILE_PATH")
        stat_fields = Path(f"/proc/{self.proc.pid}/stat").read_bytes().rsplit(b")", 1)[1].split()
        self.assertEqual(obs["start_ticks"], int(stat_fields[19]))
        self.assertEqual(obs["ppid"], os.getpid())
        self.assertEqual(obs["executable"]["sha256"], hashlib.sha256(self.exe.read_bytes()).hexdigest())
        self.assertEqual(obs["parent"]["start_ticks"] is not None, True)
        self.assertNotEqual(obs["boot_id"], "")
        self.proc.kill()
        self.proc.wait()
        # The record is self-contained: nothing has to be re-read from /proc.
        self.assertEqual(obs["exe_name"], "sleeper")
        self.assertIn(obs["exe_ref"], audit.private_index)

    def test_pinned_dirfd_refuses_reused_or_exited_pid(self):
        fd = os.open(f"/proc/{self.proc.pid}", os.O_RDONLY | os.O_DIRECTORY)
        try:
            audit = Audit("user")
            self.assertIsNotNone(audit._process_identity(self.proc.pid, fd))
            self.proc.kill()
            self.proc.wait()
            # After exit the pinned fd cannot be redirected to a newcomer with the same PID.
            self.assertIsNone(audit._process_identity(self.proc.pid, fd))
        finally:
            os.close(fd)

    def test_finding_id_is_independent_of_pid(self):
        a, b = Audit("user"), Audit("user")
        first, _ = self._finding(a)
        self.proc.kill()
        self.proc.wait()
        self.proc = subprocess.Popen([str(self.exe), "30"])
        time.sleep(0.05)
        second, _ = self._finding(b)
        self.assertEqual(report.stable_findings([first])[0]["id"], report.stable_findings([second])[0]["id"])


class ProcessFixtures(unittest.TestCase):
    def _proc(self, root: Path, pid: str, exe: str, cmdline: bytes, uid: int = 1001):
        p = root / pid
        p.mkdir(parents=True)
        (p / "status").write_text(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t1\n")
        (p / "stat").write_text(f"{pid} (we ird) S 1 " + " ".join(["0"] * 17) + " 4242 0 0\n")
        (p / "exe").symlink_to(exe)
        (p / "cmdline").write_bytes(cmdline)

    def test_truncated_cmdline_is_incompleteness_not_clean(self):
        """B-2: flags beyond the read bound are unseen and must be reported."""
        with tempfile.TemporaryDirectory() as td:
            proc = Path(td) / "proc"
            filler = b"\0".join([b"--x=" + b"a" * 1000] * 80)
            self._proc(proc, "300", "/usr/bin/brave", b"brave\0" + filler + b"\0--no-sandbox\0")
            audit = make_audit(Path(td))
            audit.proc_root = proc
            audit.processes()
            self.assertEqual(audit.coverage[-1]["status"], "PARTIAL")
            self.assertEqual(audit.coverage[-1]["reason_codes"], {"INPUT_TRUNCATED": 1})
            self.assertEqual(audit.findings, [])

    def test_stat_with_spaces_and_parens_in_comm(self):
        self.assertEqual(collectors._parse_proc_stat(b"7 (a ) b) S 3 " + b"0 " * 17 + b"99 0"), (3, 99))
        self.assertIsNone(collectors._parse_proc_stat(b"garbage"))

    def test_other_account_and_setuid_processes_are_scope_limits(self):
        with tempfile.TemporaryDirectory() as td:
            proc = Path(td) / "proc"
            proc.mkdir()
            p = proc / "400"
            p.mkdir()
            (p / "status").write_text("Name:\tx\nUid:\t1001\t0\t0\t0\nPPid:\t1\n")
            audit = make_audit(Path(td))
            audit.proc_root = proc
            with patch.object(collectors.os, "readlink", side_effect=PermissionError):
                audit.processes()
            self.assertEqual(audit.coverage[-1]["status"], "COMPLETED")
            self.assertEqual(audit.coverage[-1]["scope_limits"], {"OTHER_ACCOUNTS_NOT_VISIBLE": 1})


class BrowserFlagSemantics(unittest.TestCase):
    """B-3: a debugging pipe is not a port; a port is checked against listeners."""

    def test_pipe_is_not_network(self):
        r = detectors.browser_flag_review(["chrome", "--no-sandbox", "--remote-debugging-pipe"])
        self.assertEqual((r["debug_channel"], r["debug_port"], r["sandbox_reduced"]), ("pipe", None, True))
        self.assertIn("no network port", r["hypothesis"])
        self.assertNotIn("TCP", r["hypothesis"])

    def test_port_listener_correlation(self):
        audit = make_audit(Path("/nonexistent"))
        audit.finding("UNSAFE_BROWSER_LAUNCH_FLAG", "medium", "h", "/proc/1/cmdline",
                      {"debug_port": "9222", "debug_port_listener": "NOT_CORRELATED"}, kind="EXPOSURE")
        audit.checked("network", "COMPLETED", "fixture")
        for listeners, expected in (({"9222": {"loopback"}}, "LISTENING_LOOPBACK_ONLY"),
                                    ({"9222": {"loopback", "wildcard"}}, "LISTENING_BEYOND_LOOPBACK"),
                                    ({}, "NOT_OBSERVED")):
            audit.listening_ports = listeners
            audit._correlate_debug_ports()
            self.assertEqual(audit.findings[0]["evidence"]["debug_port_listener"], expected)
        audit.coverage[-1]["status"] = "FAILED"
        audit._correlate_debug_ports()
        self.assertEqual(audit.findings[0]["evidence"]["debug_port_listener"], "UNKNOWN")


class ChromiumIdentity(unittest.TestCase):
    """B-4/B-11: extension identity and state without manual digging."""

    ID = "a" * 32

    def _profile(self, home: Path, name: str, setting: dict | None):
        prof = home / ".config/google-chrome" / name
        ver = prof / "Extensions" / self.ID / "2.1.0_0"
        ver.mkdir(parents=True)
        (ver / "manifest.json").write_text(json.dumps({
            "manifest_version": 3, "name": "__MSG_appName__", "default_locale": "en", "version": "2.1.0",
            "permissions": ["cookies", "nativeMessaging"], "host_permissions": ["<all_urls>"],
            "content_scripts": [{"matches": ["https://*/*"]}]}))
        (ver / "_locales/en").mkdir(parents=True)
        (ver / "_locales/en/messages.json").write_text(json.dumps({"appName": {"message": "Fixture Helper"}}))
        (prof / "Extensions" / "Temp").mkdir()
        if setting is not None:
            (prof / "Preferences").write_text(json.dumps({"extensions": {"settings": {self.ID: setting}}}))
        return prof

    def test_custom_named_profile_and_full_identity(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            self._profile(home, "Work-Profile", {"disable_reasons": [], "location": 1, "from_webstore": True,
                                                 "granted_permissions": {"api": ["cookies"], "explicit_host": ["<all_urls>"]},
                                                 "withholding_permissions": False})
            audit = make_audit(home)
            audit.native_hosts_by_extension = {self.ID: {"org.fixture.host"}}
            gaps = Gaps()
            count, profiles, truncated = audit._scan_chromium("chrome", home / ".config/google-chrome", gaps)
            self.assertEqual((count, profiles, truncated), (1, 1, False))
            self.assertEqual(dict(gaps.incomplete), {}, "Temp staging folder must not be a gap")
            ext = audit.findings[0]["evidence"]["extension"]
            self.assertEqual(ext["name"], "Fixture Helper")
            self.assertEqual(ext["name_source"], "default_locale")
            self.assertEqual((ext["enabled"], ext["install_location"], ext["from_webstore"]), (True, "INTERNAL", True))
            self.assertEqual(ext["granted"]["explicit_host"], ["<all_urls>"])
            self.assertEqual(ext["content_script_matches"], ["https://*/*"])
            self.assertEqual(ext["native_hosts_allowing"], ["org.fixture.host"])

    def test_disabled_extension_is_inventoried_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            self._profile(home, "Default", {"disable_reasons": [1]})
            audit = make_audit(home)
            self.assertEqual(audit._scan_chromium("chrome", home / ".config/google-chrome")[0], 1)
            self.assertEqual(audit.findings, [])
            self.assertEqual(len(audit.baseline["browser_extensions"]), 1)

    def test_missing_preferences_means_unknown_state(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            self._profile(home, "Default", None)
            audit = make_audit(home)
            audit._scan_chromium("chrome", home / ".config/google-chrome")
            self.assertEqual(audit.findings[0]["evidence"]["extension"]["enabled"], "UNKNOWN")
            self.assertEqual(audit.findings[0]["evidence"]["extension"]["granted"], "UNKNOWN")


class FirefoxAndNativeHosts(unittest.TestCase):
    def test_firefox_identity_and_signature(self):
        with tempfile.TemporaryDirectory() as td:
            prof = Path(td) / "ff/abc.default-release"
            prof.mkdir(parents=True)
            (prof / "extensions.json").write_text(json.dumps({"addons": [
                {"id": "x@fixture", "type": "extension", "version": "3", "active": True, "signedState": 2,
                 "location": "app-profile", "defaultLocale": {"name": "Fixture"},
                 "userPermissions": {"permissions": ["cookies"], "origins": ["<all_urls>"]},
                 "optionalPermissions": {"permissions": ["history"]}},
                {"id": "off@fixture", "type": "extension", "active": False, "userDisabled": True,
                 "userPermissions": {"permissions": ["cookies"], "origins": ["<all_urls>"]}}]}))
            audit = make_audit(Path(td))
            audit._scan_firefox(Path(td) / "ff", "firefox")
            self.assertEqual(len(audit.findings), 1)
            ext = audit.findings[0]["evidence"]["extension"]
            self.assertEqual((ext["name"], ext["signed_state"], ext["optional_permissions"]), ("Fixture", "SIGNED", ["history"]))

    def test_native_host_links_and_home_prefix_boundary(self):
        """B-5: /home/userx is not inside /home/user."""
        # Fixtures may sit under /tmp; isolate the home-prefix rule from the temp-path rule.
        patcher = patch.object(detectors, "SUSPICIOUS_PATHS", ("/nonexistent-volatile/",))
        patcher.start()
        self.addCleanup(patcher.stop)
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "user"
            hosts = home / ".config/google-chrome/NativeMessagingHosts"
            hosts.mkdir(parents=True)
            exe = home / "bin/host"
            exe.parent.mkdir()
            exe.write_bytes(b"#!/bin/false\n")
            (hosts / "a.json").write_text(json.dumps({"name": "org.fixture.a", "path": str(exe),
                                                      "allowed_origins": [f"chrome-extension://{'b' * 32}/"]}))
            (hosts / "b.json").write_text(json.dumps({"name": "org.fixture.b", "path": str(Path(td) / "userx/bin/h")}))
            audit = make_audit(home)
            audit._native_hosts(Gaps())
            # System-wide host folders of the test machine are scanned too; look only at ours.
            ours = [f for f in audit.findings if f["evidence"]["host_name"].startswith("org.fixture.")]
            self.assertEqual([f["evidence"]["host_name"] for f in ours], ["org.fixture.a"])
            ev = ours[0]["evidence"]
            self.assertEqual(ev["allowed_extensions"], ["b" * 32])
            self.assertEqual(ev["manifest_owner"], "chrome")
            self.assertEqual(ev["executable"]["sha256"], hashlib.sha256(b"#!/bin/false\n").hexdigest())
            self.assertEqual(audit.native_hosts_by_extension["b" * 32], {"org.fixture.a"})


class CoverageVocabulary(unittest.TestCase):
    """B-9/C-1/C-2: status follows evidence; codes are a closed vocabulary."""

    def setUp(self):
        self.audit = make_audit(Path("/nonexistent"))

    def test_partial_requires_reason_and_completed_forbids_one(self):
        with self.assertRaises(ValueError):
            self.audit.checked("x", "PARTIAL", "d")
        with self.assertRaises(ValueError):
            self.audit.checked("x", "COMPLETED", "d", reasons=["TIMEOUT"])
        with self.assertRaises(ValueError):
            Gaps().add("MADE_UP_CODE")

    def test_scope_limits_do_not_make_partial_but_are_reported(self):
        g = Gaps()
        g.add("OTHER_ACCOUNTS_NOT_VISIBLE", 3)
        self.audit.conclude("network", "d", g)
        self.assertEqual(self.audit.coverage[-1]["status"], "COMPLETED")
        self.assertEqual(self.audit.coverage[-1]["scope_limits"], {"OTHER_ACCOUNTS_NOT_VISIBLE": 3})

    def test_every_code_has_ukrainian_explanation(self):
        codes = set(collectors.INCOMPLETE_CODES) | set(collectors.SCOPE_LIMIT_CODES) | set(collectors.SKIP_CODES)
        self.assertEqual(codes - set(guide.REASONS_UA), set())

    def test_verdict_reachable_when_only_scope_limits_remain(self):
        coverage = [{"check": c, "status": "COMPLETED", "scope_limits": {"REQUIRES_SYSTEM_SCOPE": 1}}
                    for c in ("processes", "network", "persistence", "browsers", "auth", "packages")]
        self.assertEqual(detectors.interpret_verdict([], coverage), "NO_COMPROMISE_INDICATORS_OBSERVED")
        coverage[0] = {"check": "processes", "status": "PARTIAL", "reason_codes": {"TIMEOUT": 1}}
        self.assertEqual(detectors.interpret_verdict([], coverage), "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")


class ShellFollowAndAttestation(unittest.TestCase):
    def test_sourced_user_file_is_analysed(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / ".bashrc").write_text('[ -f ~/.extra ] && . ~/.extra\nsource "$UNKNOWN/x"\n')
            (home / ".extra").write_text("bash /tmp/payload\n")
            audit = make_audit(home)
            audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "", "stderr": "no crontab for nobody",
                                             "exit": 1, "truncated": False, "error": ""}
            with patch.object(audit, "_files", return_value=([], False)):
                audit.persistence()
            shell = [f for f in audit.findings if f["rule"] == "SUSPICIOUS_SHELL_INIT"]
            self.assertEqual([f["evidence"]["file_name"] for f in shell], [".extra"])
            self.assertIn("PARSE_UNSUPPORTED", audit.coverage[-1]["reason_codes"])  # unresolved $UNKNOWN

    def test_package_attestation_requires_root_chain_and_matching_md5(self):
        audit = make_audit(Path("/nonexistent"))
        target = Path("/etc/hostname") if Path("/etc/hostname").is_file() else Path("/etc/os-release").resolve()
        content = target.read_bytes()
        audit._dpkg_index = {target.as_posix(): hashlib.md5(content).hexdigest()}
        self.assertTrue(audit.package_attested(target, content))
        self.assertFalse(audit.package_attested(target, content + b"x"))
        with tempfile.NamedTemporaryFile() as user_file:
            audit._dpkg_index[user_file.name] = hashlib.md5(b"").hexdigest()
            self.assertFalse(audit.package_attested(Path(user_file.name), b""))

    def test_vendor_user_units_are_inspected_roots(self):
        audit = make_audit(Path("/nonexistent"))
        seen = []
        audit.command = lambda *a, **k: {"status": "COMPLETED", "stdout": "", "stderr": "", "exit": 0,
                                         "truncated": False, "error": ""}

        def capture(bases, **kw):
            seen.append([str(b) for b in bases])
            return [], False
        with patch.object(audit, "_files", side_effect=capture):
            audit.persistence()
        if Path("/usr/lib/systemd/user").is_dir():
            self.assertIn("/usr/lib/systemd/user", seen[0])


class ReportContracts(unittest.TestCase):
    def _fixture_audit(self):
        audit = make_audit(Path("/nonexistent"))
        for check in ("processes", "network", "persistence", "browsers", "auth", "packages"):
            audit.checked(check, "COMPLETED", "fixture")
        audit.baseline["listeners"] = ["tcp/22/wildcard"]
        return audit

    def test_baseline_tamper_with_recomputed_manifest_is_rejected(self):
        """C-5: an edited baseline no longer matches the report's own digest."""
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "run"
            run.mkdir(mode=0o700)
            report.write_reports(run, self._fixture_audit())
            summary = json.loads((run / "summary.json").read_text())
            summary["baseline"]["listeners"] = []
            os.chmod(run / "summary.json", 0o600)
            (run / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            entries = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
                       for p in sorted(run.iterdir()) if p.name != "evidence_manifest.sha256"]
            (run / "evidence_manifest.sha256").write_text("\n".join(entries) + "\n")
            self.assertFalse(report.verify_reports(run)["verified"])

    def test_incompatible_compare_is_refused_before_collection(self):
        """C-6: field names are reported and no scan runs."""
        old = {"schema": report.SCHEMA, "tool_version": "0.0.0", "rule_set_version": "0.0.0",
               "scope": "user", "profile": "deep", "target_uid": 1001}
        audit = SimpleNamespace(uid=1001, scan=lambda **_: self.fail("scan must not start"))
        with patch.object(cli, "Audit", return_value=audit), \
             patch.object(cli, "load_verified_summary", return_value=old), \
             patch.object(cli, "create_run_directory", side_effect=AssertionError("no run dir")), \
             patch("sys.stderr", io.StringIO()) as err:
            code = cli.main(["scan", "--profile", "standard", "--compare", "/tmp/x/summary.json"])
        self.assertEqual(code, 2)
        self.assertIn("profile", err.getvalue())
        self.assertIn("tool_version", err.getvalue())

    def test_markdown_neutralises_html_and_terminal_controls(self):
        """C-8."""
        cell = report._safe_markdown('<img src=http://x>\x1b]0;t\x07|`')
        self.assertNotIn("<img", cell)
        self.assertNotIn("\x1b", cell)
        self.assertNotIn("|", cell.replace("∣", ""))

    def test_markdown_marks_omitted_findings(self):
        """C-9."""
        findings = [{"id": f"F-{i}", "rule": "R", "kind": "CONTEXT", "source_ref": "s"} for i in range(360)]
        summary = {"outcome": "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS", "finding_counts_by_kind": {},
                   "material_coverage_gaps": [], "profile": "quick", "scope": "user", "created_utc": "t",
                   "analysis_digest_sha256": "0", "cannot_exclude": []}
        text = report.build_markdown(summary, findings, [], [])
        self.assertIn("ще 10 знахідок лише у findings.json", text)

    def test_identical_findings_merge_observations_deterministically(self):
        """C-7: per-run attribution never changes identity or the digest."""
        base = {"rule": "R", "severity": "low", "kind": "CONTEXT", "evidence": {"x": 1}}
        a = [dict(base, observations=[{"pid": 2}]), dict(base, observations=[{"pid": 1}])]
        b = [dict(base, observations=[{"pid": 7}])]
        merged = report.stable_findings(a)
        self.assertEqual(len(merged), 1)
        self.assertEqual([o["pid"] for o in merged[0]["observations"]], [1, 2])
        self.assertEqual(merged[0]["id"], report.stable_findings(b)[0]["id"])
        self.assertEqual(report._analysis_digest(a, []), report._analysis_digest(b, []))


class GuideCompleteness(unittest.TestCase):
    def test_every_emitted_rule_has_an_interpretation(self):
        source = "".join((ROOT / "falsicore" / name).read_text() for name in ("collectors.py", "detectors.py"))
        emitted = set(re.findall(r'self\.finding\(\s*"([A-Z_]+)"', source))
        emitted |= set(re.findall(r'out\.append\(\("([A-Z_]+)"', source))
        emitted |= set(re.findall(r'^\s*\("([A-Z_]{8,})", "(?:low|medium|high|critical)"\)', source, re.M))
        self.assertGreaterEqual(len(emitted), 20)
        self.assertEqual(emitted - set(guide.RULES), set())

    def test_entries_are_complete_and_non_destructive(self):
        for name, entry in guide.RULES.items():
            self.assertEqual(set(entry), {"priority", "observed", "benign", "uncertainty", "action"}, name)
            self.assertIn(entry["priority"], ("P1", "P2", "P3"))
            self.assertNotRegex(entry["action"].lower(), r"\brm -|видалити файл|uninstall|kill ")


class LegacyReports(unittest.TestCase):
    """§5.9: an older schema is identified as such, never as tampering, never compared."""

    def test_v3_report_is_read_only_and_labelled(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "run"
            run.mkdir(mode=0o700)
            audit = make_audit(Path("/nonexistent"))
            audit.checked("auth", "COMPLETED", "fixture")
            report.write_reports(run, audit)
            summary = json.loads((run / "summary.json").read_text())
            summary["schema"] = "falsicore.summary.v3"
            (run / "summary.json").write_text(json.dumps(summary))
            entries = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
                       for p in sorted(run.iterdir()) if p.name != "evidence_manifest.sha256"]
            (run / "evidence_manifest.sha256").write_text("\n".join(entries) + "\n")
            out = io.StringIO()
            with patch("sys.stdout", out):
                self.assertEqual(cli.main(["explain", str(run)]), 0)
            self.assertIn("LEGACY REPORT", out.getvalue())
            out = io.StringIO()
            with patch("sys.stdout", out):
                self.assertEqual(cli.main(["verify", str(run)]), 0)
            self.assertIn("LEGACY", out.getvalue())
            (run / "report.md").write_text("tampered")
            with patch("sys.stderr", io.StringIO()), patch("sys.stdout", io.StringIO()):
                self.assertEqual(cli.main(["explain", str(run)]), 2)


class PackageVerifyAndLauncher(unittest.TestCase):
    """R-7: dpkg --verify line classes; R-6: launcher options imply a scan."""

    def test_dpkg_verify_line_classes(self):
        out = ("??5?????? c /etc/a.conf\n??5?????? /usr/bin/b\nmissing     /lib/modules/6.8.0-1/x.ko\n"
               "missing   c /etc/gone.conf\n????????? /usr/lib/secret\nweird line\n"
               "missing     /etc/private/key (Permission denied)\n")
        r = detectors.dpkg_verify_review(out)
        self.assertEqual((r["content_changed_conffiles"], r["content_changed_other_files"], r["missing_files"],
                          r["unverifiable"], r["unparsed_lines"]), (1, 1, 2, 2, 1))
        self.assertEqual(r["missing_by_prefix"], {"/etc/gone.conf": 1, "/lib/modules/6.8.0-1": 1})

    def test_missing_files_are_context_not_drift(self):
        audit = make_audit(Path("/nonexistent"), profile="deep")
        audit._files = lambda *a, **k: ([], False)
        audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "missing     /lib/modules/old/x.ko\n" * 3,
                                         "stderr": "", "exit": 1, "truncated": False, "error": ""}
        audit.packages()
        self.assertEqual([(f["rule"], f["kind"]) for f in audit.findings], [("DPKG_FILES_MISSING", "CONTEXT")])
        self.assertEqual(audit.coverage[-1]["scope_limits"], {})

    def test_launcher_options_default_to_user_scan(self):
        from falsicore import bundle
        seen = []
        with patch.object(bundle, "read_verified_bundle", return_value={}), \
             patch("falsicore.cli.main", side_effect=lambda a: seen.append(a) or 0):
            bundle.main(["--profile", "deep"])
            bundle.main([])
            bundle.main(["explain", "/x"])
        self.assertEqual(seen[0], ["scan", "--scope", "user", "--auto-compare", "--profile", "deep"])
        self.assertEqual(seen[1], ["scan", "--scope", "user", "--auto-compare"])
        self.assertEqual(seen[2], ["explain", "/x"])


if __name__ == "__main__":
    unittest.main()
