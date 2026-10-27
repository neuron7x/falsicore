"""Failure and boundary paths of collectors: unreadable, oversized, malformed,
symlinked, over-budget. Fixtures only; nothing outside temporary folders changes."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import collectors
from falsicore.collectors import Audit, Gaps

ROOT_IS_USER = os.geteuid() != 0


def make_audit(home: Path, uid: int | None = None, profile: str = "standard") -> Audit:
    uid = os.getuid() if uid is None else uid
    with patch("falsicore.collectors.os.geteuid", return_value=uid), \
         patch("falsicore.collectors.os.getuid", return_value=uid):
        audit = Audit("user", target_user="nobody", profile=profile)
    audit.home = home
    audit.uid = uid
    audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "", "stderr": "no crontab for nobody",
                                     "exit": 1, "truncated": False, "error": ""}
    return audit


class ReadGapClassification(unittest.TestCase):
    def test_status_to_code_table(self):
        with tempfile.TemporaryDirectory() as td:
            own = Path(td) / "own"
            own.write_text("x")
            audit = make_audit(Path(td))
            for status, code in (("TOO_LARGE", "INPUT_TRUNCATED"), ("SYMLINK_OR_NOT_DIRECTORY", "SYMLINK_NOT_FOLLOWED"),
                                 ("NOT_REGULAR", "MALFORMED_INPUT"), ("FAILED", "READ_FAILED"),
                                 ("PERMISSION_DENIED", "PERMISSION_DENIED")):
                g = Gaps()
                audit.read_gap(own, status, g)
                self.assertEqual(dict(g.incomplete), {code: 1}, status)
            g = Gaps()
            audit.read_gap(own, "ABSENT", g)
            self.assertEqual((dict(g.incomplete), dict(g.limits)), ({}, {}))
            foreign = make_audit(Path(td), uid=os.getuid() + 1)
            g = Gaps()
            foreign.read_gap(own, "PERMISSION_DENIED", g)
            self.assertEqual(dict(g.limits), {"OTHER_ACCOUNTS_NOT_VISIBLE": 1})
            g = Gaps()
            audit.read_gap(Path(td) / "vanished", "PERMISSION_DENIED", g)
            self.assertEqual(dict(g.incomplete), {"PERMISSION_DENIED": 1})

    def test_command_gap_table(self):
        for result, code in (({"status": "UNAVAILABLE"}, "TOOL_MISSING"), ({"status": "SKIPPED"}, "BUDGET_EXHAUSTED"),
                             ({"status": "PARTIAL", "truncated": True}, "INPUT_TRUNCATED"),
                             ({"status": "FAILED", "error": "timeout"}, "TIMEOUT"),
                             ({"status": "FAILED", "error": ""}, "TOOL_FAILED")):
            g = Gaps()
            Audit.command_gap(result, g)
            self.assertEqual(dict(g.incomplete), {code: 1}, result)


class BudgetOverrun(unittest.TestCase):
    def test_collector_finishing_after_deadline_becomes_partial(self):
        audit = make_audit(Path("/nonexistent"), profile="quick")

        def slow(self):
            self.checked("environment", "COMPLETED", "fixture")
            self.deadline = 0.0  # the deadline passed while this collector ran
        others = {n: (lambda self, n=n: self.checked(n, "COMPLETED", "fixture"))
                  for n in audit.profile_config["checks"] if n != "environment"}
        with patch.multiple(Audit, environment=slow, **others):
            audit.scan()
        env = next(c for c in audit.coverage if c["check"] == "environment")
        self.assertEqual((env["status"], env["reason_codes"]), ("PARTIAL", {"BUDGET_EXHAUSTED": 1}))
        budget_skipped = [c for c in audit.coverage if c["status"] == "SKIPPED" and "BUDGET_EXHAUSTED" in c["reason_codes"]]
        self.assertEqual(len(budget_skipped), len(audit.profile_config["checks"]) - 1)


@unittest.skipUnless(Path("/var/lib/dpkg/info").is_dir(), "dpkg database not present")
class DpkgIndex(unittest.TestCase):
    def test_index_matches_an_installed_binary(self):
        audit = make_audit(Path("/nonexistent"))
        target = Path("/usr/bin/dpkg")
        expected = audit._dpkg_md5(target)
        self.assertIsNotNone(expected)
        self.assertEqual(expected, hashlib.md5(target.read_bytes()).hexdigest())
        self.assertIsNone(audit._dpkg_md5(Path("/nonexistent/file")))


class PersistenceFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()

    def tearDown(self):
        for p in self.root.rglob("*"):
            try:
                os.chmod(p, 0o700)
            except OSError:
                pass
        self.tmp.cleanup()

    def _run(self, cron: list[Path] = (), autostart: list[Path] = ()):
        audit = make_audit(self.home)

        def files(bases, **kw):
            names = {str(b) for b in bases}
            if any("cron" in n for n in names):
                return list(cron), False
            if any("autostart" in n for n in names):
                return list(autostart), False
            return [], False
        with patch.object(audit, "_files", side_effect=files):
            audit.persistence()
        return audit

    def test_cron_and_autostart_findings_and_limits(self):
        cron = self.root / "job"
        cron.write_text("* * * * * bash /tmp/x\n")
        expanded = self.root / "expanded"
        expanded.write_text("* * * * * $CMD\n")
        desktop = self.root / "a.desktop"
        desktop.write_text("[Desktop Entry]\nExec=/tmp/agent %U\n")
        audit = self._run([cron, expanded], [desktop])
        rules = {f["rule"] for f in audit.findings}
        self.assertTrue({"SUSPICIOUS_CRON_EXECUTION", "SUSPICIOUS_AUTOSTART"} <= rules)
        self.assertEqual(audit.coverage[-1]["reason_codes"].get("PARSE_UNSUPPORTED"), 1)

    @unittest.skipUnless(ROOT_IS_USER, "root bypasses file modes")
    def test_unreadable_own_cron_file_is_permission_gap(self):
        cron = self.root / "locked"
        cron.write_text("* * * * * true\n")
        os.chmod(cron, 0)
        audit = self._run([cron])
        self.assertEqual(audit.coverage[-1]["reason_codes"].get("PERMISSION_DENIED"), 1)

    def test_sourced_file_outside_home_is_followed_when_not_attested(self):
        other = self.root / "elsewhere.sh"
        other.write_text("source /tmp/payload\n")
        (self.home / ".bashrc").write_text(f". {other}\nsource /absent/file\n")
        audit = self._run()
        self.assertIn("SUSPICIOUS_SHELL_INIT", {f["rule"] for f in audit.findings})
        self.assertNotIn("PARSE_UNSUPPORTED", audit.coverage[-1]["reason_codes"])

    def test_shell_file_limit_is_reported(self):
        # Fixture paths may live under /tmp (TMPDIR unset in self-test, CI); that
        # must not turn the sourced chain into TEMP_PATH findings instead.
        patcher = patch("falsicore.shell_syntax.TEMP_PREFIXES", ("/nonexistent-volatile/",))
        patcher.start()
        self.addCleanup(patcher.stop)
        chain = [self.home / f".r{i}" for i in range(collectors.MAX_SHELL_FILES + 3)]
        for current, nxt in zip(chain, chain[1:]):
            current.write_text(f". {nxt}\n")
        chain[-1].write_text("true\n")
        (self.home / ".bashrc").write_text(f". {chain[0]}\n")
        audit = self._run()
        self.assertIn("ENUMERATION_LIMIT", audit.coverage[-1]["reason_codes"])


class ChromiumFailurePaths(unittest.TestCase):
    def test_malformed_and_unusual_extension_folders(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "chrome"
            exts = base / "Default" / "Extensions"
            exts.mkdir(parents=True)
            (base / "Default" / "Preferences").write_text("{not json")
            (exts / "as-file").write_text("x")                      # not a directory
            (exts / "noversions").mkdir()                            # no version folder
            (exts / "linked").symlink_to(exts / "noversions")        # symlinked extension
            bad = exts / "badjson" / "1.0"
            bad.mkdir(parents=True)
            (bad / "manifest.json").write_text("[]")                 # not an object
            missing = exts / "nomanifest" / "1.0"
            missing.mkdir(parents=True)
            audit = make_audit(Path(td))
            g = Gaps()
            count, profiles, truncated = audit._scan_chromium("chrome", base, g)
            self.assertTrue(truncated)
            self.assertEqual(profiles, 1)
            self.assertEqual({f["rule"] for f in audit.findings}, {"INVALID_EXTENSION_MANIFEST"})
            # Preferences JSON, file-as-extension, no version folder, no manifest.
            self.assertEqual(g.incomplete["MALFORMED_INPUT"], 4)
            self.assertEqual(g.incomplete["SYMLINK_NOT_FOLLOWED"], 1)

    def test_extension_cap_and_symlinked_base(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "chrome"
            exts = base / "Default" / "Extensions"
            for i in range(201):
                (exts / f"e{i:03d}").mkdir(parents=True)
            audit = make_audit(Path(td))
            g = Gaps()
            audit._scan_chromium("chrome", base, g)
            self.assertIn("ENUMERATION_LIMIT", g.incomplete)
            link = Path(td) / "link"
            link.symlink_to(base)
            g = Gaps()
            self.assertEqual(audit._scan_chromium("chrome", link, g), (0, 0, True))
            self.assertIn("SYMLINK_NOT_FOLLOWED", g.incomplete)


class FirefoxAndHostFailurePaths(unittest.TestCase):
    def test_firefox_malformed_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "ff"
            for name, content in (("a.default", "{"), ("b.default", json.dumps({"addons": {}})),
                                  ("c.default", json.dumps({"addons": ["x", {"type": "theme"}]}))):
                (base / name).mkdir(parents=True)
                (base / name / "extensions.json").write_text(content)
            (base / "d.default").mkdir()                                  # no extensions.json
            (base / "e.default").symlink_to(base / "d.default")
            audit = make_audit(Path(td))
            g = Gaps()
            count, truncated = audit._scan_firefox(base, "firefox", g)
            self.assertEqual((count, truncated), (0, True))
            for code in ("MALFORMED_INPUT", "SYMLINK_NOT_FOLLOWED", "READ_FAILED"):
                self.assertIn(code, g.incomplete)

    def test_native_host_malformed_manifests(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            hosts = home / ".config/chromium/NativeMessagingHosts"
            hosts.mkdir(parents=True)
            (hosts / "a.json").write_text("{")
            (hosts / "b.json").write_text("[]")
            audit = make_audit(home)
            g = Gaps()
            audit._native_hosts(g)
            self.assertGreaterEqual(g.incomplete["MALFORMED_INPUT"], 2)

    def test_file_identity_states(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "exe"
            f.write_bytes(b"x")
            self.assertEqual(Audit._file_identity(f)["sha256"], hashlib.sha256(b"x").hexdigest())
            self.assertEqual(Audit._file_identity(Path(td) / "none"), {"status": "ABSENT"})
            link = Path(td) / "l"
            link.symlink_to(f)
            self.assertTrue(Audit._file_identity(link)["is_symlink"])


if __name__ == "__main__":
    unittest.main()
