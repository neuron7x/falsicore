"""Regression contracts: literal command operands, not unrelated string matches."""
import unittest
from falsicore.shell_syntax import analyze
from falsicore.detectors import suspect_command, suspicious_systemd


class LiteralExecutionContracts(unittest.TestCase):
    pass


CASES = {
    "export_tmp_other_line_python": ("export TMPDIR=/tmp/cache\npython3 --version", []),
    "export_tmp_other_line_bash": ("export TMPDIR=/tmp/cache\nbash -l", []),
    "comment_line": ("# bash /tmp/file", []),
    "comment_inline": ("echo ok # bash /tmp/file", []),
    "data_same_line": ("echo /tmp/x; python3 --version", []),
    "quoted_print": ("printf '%s\\n' 'bash /tmp/x'", []),
    "quoted_pipe_print": ("echo 'curl https://example.invalid/a | bash'", []),
    "decode_is_data": ("base64 --decode document.txt", []),
    "quoted_direct": ("'/tmp/tool'", ["TEMP_PATH_IN_EXECUTION"]),
    "quoted_script": ('bash "/tmp/a b.sh"', ["TEMP_PATH_IN_EXECUTION"]),
    "absolute_script": ('/bin/bash /tmp/run', ["TEMP_PATH_IN_EXECUTION"]),
    "source": ("source /tmp/run", ["TEMP_PATH_IN_EXECUTION"]),
    "dot_source": (". /tmp/run", ["TEMP_PATH_IN_EXECUTION"]),
    "data_python_arg": ("python3 /home/me/tool.py /tmp/data", []),
    "data_shell_arg": ("bash /home/me/tool.sh /tmp/data", []),
    "inline_python_data": ('''python3 -c "print('/tmp/a')"''', []),
    "shell_c_echo": ('''bash -c 'echo /tmp/a' ''', []),
    "shell_c_exec": ('''bash -c 'source /tmp/a' ''', ["TEMP_PATH_IN_EXECUTION"]),
    "python_module_data": ("python3 -m json.tool /tmp/a", []),
    "env_interpreter": ("env FOO=1 python3 /tmp/a", ["TEMP_PATH_IN_EXECUTION"]),
    "sudo_interpreter": ("sudo -u nobody bash /tmp/a", ["TEMP_PATH_IN_EXECUTION"]),
    "direct_tmp_cache_argument": ("/usr/bin/true /tmp/a", []),
    "path_case_sensitive": ("bash /TMP/a", []),
    "path_normalized_benign": ("bash /tmp/../home/me/a", []),
    "path_normalized_temp": ("bash /home/../tmp/a", ["TEMP_PATH_IN_EXECUTION"]),
    "pipeline_remote": ("curl https://example.invalid/a | bash", ["REMOTE_SCRIPT_PIPELINE"]),
    "pipeline_decode": ("base64 --decode a | sh", ["BASE64_DECODE_EXECUTION_CONTEXT"]),
    "pipeline_data": ("curl https://example.invalid/a | cat", []),
    "pipeline_bash_script_ignores_stdin_code": ("curl https://example.invalid/a | bash /home/me/script", []),
    "pipeline_unrelated": ("curl https://example.invalid/a; bash", []),
    "pipeline_decode_data": ("base64 -d a > /tmp/data", []),
    "heredoc_data": ("cat <<'EOF'\nbash /tmp/a\nEOF\n", []),
    "two_heredocs_data": ("cat <<A <<B\nbash /tmp/a\nA\nbash /tmp/b\nB\n", []),
    "continued_literal": ("bash \\\n /tmp/run", ["TEMP_PATH_IN_EXECUTION"]),
    "controlled_condition": ("if true; then bash /tmp/a; fi", ["TEMP_PATH_IN_EXECUTION"]),
}


def make_test(text, expected):
    def test(self):
        self.assertEqual(suspect_command(text), expected)
        self.assertEqual(analyze(text), analyze(text))
    return test


for name, (text, expected) in CASES.items():
    setattr(LiteralExecutionContracts, "test_" + name, make_test(text, expected))


class ShellScopeContracts(unittest.TestCase):
    def test_shell_heredoc_body_is_analysed_as_code(self):
        # A here-document fed to a shell is code: analysed, not skipped.
        self.assertEqual(analyze("sh <<EOF\n/tmp/a\nEOF")["patterns"], ["TEMP_PATH_IN_EXECUTION"])
        self.assertIn("HEREDOC_EXPANSION_NOT_RESOLVED", analyze("sh <<EOF\n$X\nEOF")["limitations"])
        self.assertNotIn("HEREDOC_EXPANSION_NOT_RESOLVED", analyze("sh <<'EOF'\n$X\nEOF")["limitations"])

    def test_reports_variable_uncertainty(self):
        self.assertIn("EXPANSION_NOT_RESOLVED", analyze('bash "$TARGET"')["limitations"])

    def test_reports_parse_error(self):
        self.assertIn("UNPARSED_QUOTING", analyze("echo '")["limitations"])

    def test_source_content_not_exported(self):
        result = analyze("# comment\nsource /tmp/DO_NOT_EXPORT_SECRET_PATH\n")
        self.assertEqual(result["matches"][0]["line"], 2)
        self.assertNotIn("DO_NOT_EXPORT_SECRET_PATH", str(result))

    def test_systemd_data_argument_not_execution(self):
        self.assertEqual(suspicious_systemd("[Service]\nExecStart=/usr/bin/app --cache /tmp/cache"), [])

    def test_systemd_explicit_execution(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", suspicious_systemd("[Service]\nExecStart=/tmp/app"))

    def test_nested_eval_bound(self):
        self.assertIn("NESTING_LIMIT", analyze("eval " * 20 + "true")["limitations"])

    def test_input_bound(self):
        self.assertIn("INPUT_LIMIT", analyze(" " * 140000)["limitations"])

    def test_incomplete_continuation(self):
        self.assertIn("INCOMPLETE_CONTINUATION", analyze("echo \\")["limitations"])

    def test_unclosed_heredoc(self):
        self.assertIn("UNTERMINATED_HEREDOC", analyze("cat <<STOP\ndata")["limitations"])

    def test_comments_cannot_join_separate_execution(self):
        self.assertEqual(suspect_command("export T=/tmp/a\n# bash\necho ok"), [])


if __name__ == "__main__":
    unittest.main()
