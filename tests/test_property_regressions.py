"""Concrete counterexamples found while stating the properties in test_properties.py.

They run without Hypothesis, so the shipped self-test keeps guarding them.
Each class names the defect it refutes (register P-1.. in docs/AUDIT.md).
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore.collectors import Audit
from falsicore.report import stable_findings
from falsicore.shell_syntax import analyze


class P1_NulMarkerForgery(unittest.TestCase):
    """A NUL byte in a start-up file could forge an internal marker and crash the analyser."""

    def test_forged_procsub_marker_does_not_raise(self):
        for text in ("source \x00PROCSUBzz\x00", "python3 \x00PROCSUB9\x00", ". \x00PROCSUB\x00", "echo \x00SUB\x00"):
            result = analyze(text)
            self.assertIn("NUL_IN_INPUT", result["limitations"], text)

    def test_nul_is_removed_not_treated_as_a_word_break(self):
        # Bash drops NUL bytes; "/tmp/x\x00y" is the program /tmp/xy.
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("/tmp/x\x00y")["patterns"])

    def test_persistence_collector_survives_nul_in_bashrc(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            audit = Audit("user", target_user="nobody")
        audit.home = Path("/fixture-user")

        def read(path, *args):
            if path == audit.home / ".bashrc":
                return (b"export PATH=$PATH:~/bin\nsource \x00PROCSUBzz\x00\n", "COMPLETED")
            return (None, "ABSENT")
        response = {"status": "FAILED", "stdout": "", "stderr": "no crontab for nobody", "exit": 1,
                    "elapsed_ms": 0, "truncated": False, "error": ""}
        with patch("falsicore.collectors.safe_read", side_effect=read), \
             patch.object(audit, "_files", return_value=([], False)), \
             patch.object(audit, "command", return_value=response), \
             patch.object(Path, "is_dir", return_value=False):
            audit.persistence()
        [row] = [c for c in audit.coverage if c["check"] == "persistence"]
        self.assertNotEqual(row["status"], "FAILED")
        self.assertIn("PARSE_UNSUPPORTED", row["reason_codes"])


class P2_CommentContinuation(unittest.TestCase):
    """A comment ending in a backslash was reported as an incomplete continuation."""

    def test_comment_with_trailing_backslash_is_not_a_limitation(self):
        for text in ("# tail \\", "echo hi\n# note \\", "echo hi # c \\"):
            self.assertEqual(analyze(text)["limitations"], [], text)

    def test_real_dangling_continuation_is_still_reported(self):
        self.assertEqual(analyze("echo hi \\")["limitations"], ["INCOMPLETE_CONTINUATION"])

    def test_escaped_backslash_and_escaped_space_are_not_continuations(self):
        self.assertEqual(analyze("echo hi \\\\")["limitations"], [])
        self.assertEqual(analyze("echo a \\ b")["limitations"], [])


class P3_StableFindingsIdempotence(unittest.TestCase):
    """Stabilising an already stable list changed finding IDs and lost the omitted count."""

    def finding(self, n: int) -> dict:
        return {"id": "F0001", "rule": "R", "severity": "medium", "kind": "INDICATOR", "hypothesis": "h",
                "source_ref": "s", "evidence": {"a": 1}, "classification": "x", "attack_technique": None,
                "confirmation": "n", "alternative_explanation": "a",
                "observations": [{"pid": i} for i in range(n)]}

    def test_second_pass_keeps_ids_and_omitted_count(self):
        once = stable_findings([self.finding(25)])
        twice = stable_findings(once)
        self.assertEqual(once[0]["id"], twice[0]["id"])
        self.assertEqual(once[0]["observations_omitted"], 5)
        self.assertEqual(twice[0]["observations_omitted"], 5)
        self.assertEqual(once, twice)

    def test_omitted_count_accumulates_across_merged_duplicates(self):
        merged = stable_findings([self.finding(15), self.finding(15)])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["observations"]), 20)
        self.assertEqual(merged[0]["observations_omitted"], 10)


class P4_DigestCoverageOrder(unittest.TestCase):
    """Coverage rows that tie on (check, status) made the analysis digest depend on order."""

    def test_digest_ignores_order_of_tied_rows(self):
        from falsicore.report import _analysis_digest
        a = {"check": "processes", "status": "COMPLETED", "details": "", "reason_codes": {}, "scope_limits": {}}
        b = {**a, "scope_limits": {"REQUIRES_SYSTEM_SCOPE": 1}}
        self.assertEqual(_analysis_digest([], [a, b], {}), _analysis_digest([], [b, a], {}))


class P5_KeywordNamedProgram(unittest.TestCase):
    """A program whose basename is a shell reserved word escaped the volatile-path rule."""

    def test_volatile_program_named_like_a_keyword_is_flagged(self):
        for name in ("in", "done", "fi", "esac", "case", "for", "function"):
            self.assertIn("TEMP_PATH_IN_EXECUTION", analyze(f"/tmp/{name} --arg")["patterns"], name)

    def test_bare_keywords_are_still_not_commands(self):
        script = "if true; then\n  echo x\nfi\nfor i in 1 2; do :; done\n"
        self.assertEqual(analyze(script)["patterns"], [])


if __name__ == "__main__":
    unittest.main()
