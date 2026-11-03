"""Trust-boundary and offline source regressions for the verification act."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from falsicore.collectors import Audit
from falsicore.detectors import interpret_verdict


class PathAndProvenance(unittest.TestCase):
    def test_home_relative_prefixes_stay_inside_home(self):
        a = Audit.__new__(Audit)
        a.home = Path("/var/lib/fixture-user")
        for path in ("~/file.sh", "~//file.sh", "\x00VAR:HOME\x00/file.sh",
                     "\x00VAR:HOME\x00//file.sh"):
            self.assertEqual(a._resolve_sourced(path), a.home / "file.sh")
        for path in ("~/../etc/passwd", "~//../etc/passwd",
                     "\x00VAR:HOME\x00/../../etc/passwd"):
            self.assertIsNone(a._resolve_sourced(path))

    def test_relative_executable_never_aliases_system_package(self):
        with tempfile.TemporaryDirectory() as td:
            a = Audit.__new__(Audit)
            a.root = Path(td)
            (a.root / "usr/bin").mkdir(parents=True)
            (a.root / "usr/bin/dircolors").write_text("ok")
            a.package_attested = lambda *args: True
            self.assertIsNone(a._attested_program("./dircolors"))
            self.assertIsNone(a._attested_program("../dircolors"))
            self.assertIsNone(a._attested_program("other/dircolors"))
            self.assertIsNone(a._attested_program("dd"))
            self.assertEqual(a._attested_program("dircolors"), a.root / "usr/bin/dircolors")

    def test_offline_journal_rejects_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "image"
            root.mkdir()
            (root / "var").symlink_to(Path(td) / "outside")
            outside = Path(td) / "outside/log/journal"
            outside.mkdir(parents=True)
            a = Audit.__new__(Audit)
            a.root, a.offline = root, True
            a.command = lambda *args, **kwargs: self.fail("journalctl must not run")
            self.assertEqual(a._journal(["_TRANSPORT=kernel"], 1, 10, 5)["status"], "UNAVAILABLE")


class VerdictIntegrity(unittest.TestCase):
    def test_partial_package_check_is_not_suppressed_by_offline_scope_limit(self):
        names = {"processes", "network", "persistence", "browsers", "auth", "packages", "crossview"}
        rows = [{"check": n, "status": "COMPLETED"} for n in sorted(names)]
        for row in rows:
            if row["check"] == "packages":
                row.update(status="PARTIAL", scope_limits={"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1},
                           reason_codes={"READ_FAILED": 1})
            elif row["check"] in {"processes", "network", "crossview"}:
                row.update(status="SKIPPED", scope_limits={"LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": 1})
        self.assertEqual(interpret_verdict([], rows), "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")


if __name__ == "__main__":
    unittest.main()
