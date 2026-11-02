"""The mutation tool itself: operators, selection, diff parsing, annotations.

End-to-end execution (tree copy + subprocess) is exercised by the CI job
`mutation-diff`; here the pure parts are pinned so the tool cannot silently
stop generating a class of mutants or silently waive annotated lines.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import mutate

SNIPPET = '''
LIMIT = 10

def check(values, flag=True):
    total = 0
    for v in values:
        if v < 0:
            continue
        total += v
    if flag and total > LIMIT:   # no mutate: documentation example
        return "over"
    log(total)
    return "ok" if total == 0 else "some"
'''


class Generation(unittest.TestCase):
    def test_every_operator_class_appears_and_output_compiles(self):
        mutants = mutate.generate("snippet", SNIPPET)
        operators = {m.operator.split(":")[0] for m in mutants}
        for expected in ("compare", "boolop", "int", "return", "continue->break", "augassign", "call", "if", "bool"):
            self.assertIn(expected, operators, expected)
        for m in mutants:
            self.assertEqual(m.status, "PENDING")
            ast.parse(m.detail)   # the mutated module is valid Python
            self.assertNotEqual(m.detail, SNIPPET)

    def test_line_restriction_and_identities_are_unique(self):
        mutants = mutate.generate("snippet", SNIPPET, lines={7})
        self.assertTrue(mutants)
        self.assertTrue(all(m.line == 7 for m in mutants))
        ids = [m.mutant_id for m in mutate.generate("snippet", SNIPPET)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_legacy_line_annotation_never_waives_any_mutant(self):
        mutants = mutate.generate("snippet", SNIPPET, lines={10})
        self.assertTrue(mutants)
        self.assertIn("boolop:swap", {m.operator for m in mutants})
        self.assertTrue(all(m.status == "PENDING" for m in mutants))
        self.assertTrue(all(m.detail != SNIPPET for m in mutants))
        bare = mutate.generate("s", "x = 1  # no mutate:\n")
        self.assertTrue(bare)
        self.assertTrue(all(m.status == "PENDING" for m in bare))

    def test_real_safety_source_annotations_cannot_hide_mutants(self):
        source = (mutate.PACKAGE / "safety.py").read_text()
        candidates = [m for m in mutate.generate("safety", source)
                      if "# no mutate:" in m.original]
        self.assertGreater(len(candidates), 10)
        self.assertTrue(all(m.status == "PENDING" for m in candidates))

    def test_obsolete_annotation_status_is_rejected_instead_of_skipped(self):
        mutant = mutate.Mutant("safety", 1, "int:shift", "x = 1", "0", "example",
                               status="ANNOTATED")
        result = mutate.run_mutant(mutant, None, Path("/nonexistent-waiver-test"),
                                   sys.executable, timeout=1)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("waiver", result.detail)

    def test_child_stdout_zero_read_mutant_is_executed_and_killed(self):
        """FC-23: 65536 -> 0 is observable, never eligible for a blanket waiver."""
        source = (mutate.PACKAGE / "safety.py").read_text()
        zeros = [
            m for m in mutate.generate("safety", source)
            if m.operator == "int:shift" and m.mutated == "0"
            and "os.read(key.fd, min(0," in m.detail
        ]
        self.assertEqual(len(zeros), 1, "expected exactly one child-pipe read bound")
        mutant = zeros[0]
        self.assertNotEqual(mutant.status, "ANNOTATED")
        with tempfile.TemporaryDirectory(prefix="fc23-child-stdout-") as td:
            checkout = Path(td) / "checkout"
            mutate._fresh_tree(checkout)
            result = mutate.run_mutant(
                mutant, {"test_executor_lifecycle.ExecutorLifecycleTests.test_stderr_is_separate_from_parsed_stdout"},
                checkout, sys.executable, timeout=30
            )
        self.assertEqual(result.status, "KILLED", result.detail)

    def test_strings_are_never_mutated(self):
        mutants = mutate.generate("s", 'MESSAGE = "do not touch"\n')
        self.assertEqual(mutants, [])

    def test_mutated_source_differs_exactly_at_the_site(self):
        mutants = [m for m in mutate.generate("s", "def f(a):\n    return a < 3\n") if m.operator.startswith("compare")]
        self.assertEqual(len(mutants), 1)
        self.assertIn("a <= 3", mutants[0].detail)

    def test_continuation_line_selects_enclosing_boolean_operator(self):
        sample = "def f(a, b):\n    return (a\n            and b)\n"
        selected = mutate.generate("example", sample, lines={3})
        self.assertTrue(any(m.operator == "boolop:swap" for m in selected))

    def test_mutations_leave_unrelated_lexical_bytes_unchanged(self):
        sample = "# REGEX-SENSITIVE: exact annotation\ndef f(a):\n    return a == 1\n"
        selected = [m for m in mutate.generate("example", sample) if m.operator.startswith("compare")]
        self.assertTrue(selected)
        for m in selected:
            self.assertTrue(m.detail.startswith("# REGEX-SENSITIVE: exact annotation\n"))


class Selection(unittest.TestCase):
    def test_covering_tests_come_from_coverage_contexts(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "coverage.json"
            path.write_text(json.dumps({"files": {"/x/falsicore/detectors.py": {"contexts": {
                "10": ["test_a.T.test_1", "test_b.T.test_2"], "11": [""], "12": []}}}}))
            table = mutate.covering_tests(path, "detectors")
            self.assertEqual(table[10], {"test_a.T.test_1", "test_b.T.test_2"})
            self.assertEqual(table[11], set())     # import time only: no test
            self.assertEqual(table[12], set())
            self.assertEqual(mutate.covering_tests(path, "report"), {})
            self.assertIsNone(mutate.covering_tests(Path(td) / "missing.json", "detectors"))

    def test_parse_diff_collects_added_lines_per_module(self):
        diff = ("diff --git a/falsicore/detectors.py b/falsicore/detectors.py\n"
                "--- a/falsicore/detectors.py\n+++ b/falsicore/detectors.py\n"
                "@@ -10,0 +11,3 @@\n+a\n+b\n+c\n@@ -40 +44 @@\n-x\n+y\n"
                "diff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -1 +1 @@\n")
        self.assertEqual(mutate.parse_diff(diff), {"detectors": {11, 12, 13, 44}})
        self.assertEqual(mutate.parse_diff(""), {})


class Reporting(unittest.TestCase):
    def test_markdown_lists_open_items_only(self):
        result = {"modules": ["m"], "counts": {"KILLED": 2, "SURVIVED": 1}, "mutation_score": 0.6667,
                  "test_selection": True, "wall_clock_seconds": 1.0,
                  "mutants": [{"mutant_id": "m:1:1:x", "operator": "x", "original": "o", "mutated": "p",
                               "status": "KILLED", "tests": 1, "detail": ""},
                              {"mutant_id": "m:2:1:y", "operator": "y", "original": "o2", "mutated": "p2",
                               "status": "SURVIVED", "tests": 3, "detail": ""}]}
        text = mutate.markdown(result)
        self.assertIn("m:2:1:y", text)
        self.assertNotIn("m:1:1:x", text)
        self.assertIn("score 0.6667", text)


class Retry(unittest.TestCase):
    def test_open_signatures_and_retention_follow_text_not_lines(self):
        result = {"mutants": [
            {"module": "snippet", "operator": "compare:Lt->LtE", "original": "if v < 0:", "mutated": "v <= 0", "status": "SURVIVED"},
            {"module": "snippet", "operator": "int:shift", "original": "LIMIT = 10", "mutated": "11", "status": "KILLED"},
            {"module": "snippet", "operator": "call:delete", "original": "log(total)", "mutated": "pass", "status": "NO_TESTS"},
            {"module": "other", "operator": "bool:flip", "original": "x = True", "mutated": "False", "status": "ERROR"}]}
        signatures = mutate.open_signatures(result)
        self.assertEqual(set(signatures), {"snippet", "other"})
        self.assertEqual(len(signatures["snippet"]), 2)
        moved = "\n\n\n" + SNIPPET            # an unrelated edit above: every line number shifts
        retained = mutate.retain(mutate.generate("snippet", moved), signatures["snippet"])
        self.assertEqual(sorted((m.operator, m.mutated) for m in retained),
                         [("call:delete", "pass"), ("compare:Lt->LtE", "v <= 0")])
        self.assertEqual(mutate.retain(mutate.generate("snippet", SNIPPET), set()), [])

    def test_retry_with_nothing_open_runs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            earlier = Path(tmp) / "run.json"
            earlier.write_text(json.dumps({"mutants": [{"module": "m", "operator": "o", "original": "x",
                                                        "mutated": "y", "status": "KILLED"}]}))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(mutate.main(["--retry", str(earlier)]), 0)
            self.assertIn("nothing to retry", out.getvalue())

    def test_incomplete_budget_is_nonzero_even_with_survivor_waiver(self):
        mocked = {"modules": ["detectors"], "mutants": [{"status": "NOT_RUN", "module": "detectors", "line": 1,
                 "operator": "compare", "original": "x", "mutated": "y", "mutant_id": "x", "tests": 0, "detail": ""}],
                  "counts": {"NOT_RUN": 1}, "mutation_score": None, "test_selection": False,
                  "wall_clock_seconds": 0}
        with patch.object(mutate, "run", return_value=mocked), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mutate.main(["--module", "detectors", "--budget", "0", "--allow-survivors"]), 1)

    def test_read_bound_zero_mutant_never_suppressed_by_line_waiver(self):
        source = ("def f(fd):\n"
                  "    return os.read(fd, min(65536, 8192))  # no mutate: read sizes pace the loop\n")
        mutants = mutate.generate("safety", source)
        zero = [m for m in mutants if m.operator == "int:shift" and m.mutated == "0"]
        self.assertTrue(zero)
        self.assertTrue(all(m.status != "ANNOTATED" for m in zero))


    def test_all_or_module_with_zero_generated_mutants_fails_closed(self):
        # A broken generator or empty selection cannot certify a full package.
        # Pre-fix --all and --module incorrectly returned exit 0 for this case.
        empty = {"modules": ["detectors"], "mutants": [], "counts": {},
                 "mutation_score": None, "test_selection": True,
                 "wall_clock_seconds": 0.0}
        with patch.object(mutate, "run", return_value=empty), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(mutate.main(["--all"]), 1)
            self.assertEqual(mutate.main(["--module", "detectors"]), 1)
        self.assertIn("NOT_MEASURED", errors.getvalue())

        # Benign twin: an actually executed and killed mutant still passes.
        killed = {**empty, "mutants": [{"status": "KILLED"}],
                  "counts": {"KILLED": 1}}
        with patch.object(mutate, "run", return_value=killed), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mutate.main(["--all"]), 0)

    def test_changed_lines_git_diff_is_time_bounded_and_still_parses(self):
        diff = ("diff --git a/falsicore/detectors.py b/falsicore/detectors.py\n"
                "+++ b/falsicore/detectors.py\n"
                "@@ -2,0 +3,1 @@\n+new_code()\n")
        with patch.object(mutate.shutil, "which", return_value="/usr/bin/git"), \
             patch.object(mutate.subprocess, "run",
                          return_value=SimpleNamespace(stdout=diff)) as git:
            self.assertEqual(mutate.changed_lines("origin/main"), {"detectors": {3}})
        self.assertTrue(git.call_args.kwargs["check"])
        self.assertEqual(git.call_args.kwargs.get("timeout"), 120)


class FailClosedMutationExecution(unittest.TestCase):
    def test_failed_manifest_generation_is_error_not_a_killed_mutant(self):
        mutant = mutate.Mutant(
            module="detectors", line=1, operator="int:shift",
            original="VALUE = 1", mutated="0", mutant_id="detectors:1:1",
            detail="VALUE = 0")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "falsicore/detectors.py"
            target.parent.mkdir()
            target.write_text("VALUE = 1")
            with patch.object(mutate.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)
            ]) as run:
                result = mutate.run_mutant(
                    mutant, {"test_x.Foo.test_value"}, root, sys.executable, timeout=1)
            self.assertEqual(result.status, "ERROR")
            self.assertEqual(result.detail, "RuntimeError")
            self.assertEqual(target.read_text(), "VALUE = 1")
            self.assertEqual(run.call_count, 1)

    def test_timeout_is_never_a_success_even_in_measurement_mode(self):
        row = {"module": "detectors", "line": 1, "operator": "compare",
               "original": "x", "mutated": "y", "mutant_id": "x",
               "status": "TIMEOUT", "tests": 1, "detail": "120s"}
        report = {"modules": ["detectors"], "mutants": [row],
                  "counts": {"TIMEOUT": 1}, "mutation_score": 0.0,
                  "test_selection": True, "wall_clock_seconds": 0.0}
        with patch.object(mutate, "run", return_value=report), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mutate.main([
                "--module", "detectors", "--allow-survivors"]), 1)
        self.assertIn(("compare", "x", "y"),
                      mutate.open_signatures(report)["detectors"])


    def test_generated_output_does_not_downgrade_kill_to_restoration_error(self):
        """Negative control: a child writes a release-disallowed file before failing."""
        mutant = mutate.Mutant("detectors", 1, "int:shift", "VALUE = 1",
                               "0", "detectors:1:1", detail="VALUE = 0")
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            target = workdir / "falsicore/detectors.py"
            target.parent.mkdir()
            target.write_text("VALUE = 1\n")
            manifest = workdir / "SOURCE_MANIFEST.sha256"
            manifest.write_bytes(b"baseline manifest\n")
            calls = []

            def command(argv, **kwargs):
                calls.append(argv)
                if "--write-manifest" in argv:
                    # The real packager would reject the unexpected file.
                    if (workdir / "unexpected-test-output.json").exists():
                        return SimpleNamespace(returncode=1)
                    manifest.write_bytes(b"mutated manifest\n")
                    return SimpleNamespace(returncode=0)
                (workdir / "unexpected-test-output.json").write_text("test residue")
                return SimpleNamespace(returncode=1, stderr="FAIL: injected_negative_control")

            with patch.object(mutate.subprocess, "run", side_effect=command):
                result = mutate.run_mutant(mutant, {"test_x.Case.test_fail"},
                                           workdir, sys.executable, timeout=2)
            self.assertEqual(result.status, "KILLED", result.detail)
            self.assertEqual(target.read_text(), "VALUE = 1\n")
            self.assertEqual(manifest.read_bytes(), b"baseline manifest\n")
            self.assertEqual(len(calls), 2)

    def test_two_mutants_start_from_independent_pristine_checkouts(self):
        """Red control: the former pooled worktree passed residue to mutant #2."""
        with tempfile.TemporaryDirectory() as td:
            pkg = Path(td) / "falsicore"
            pkg.mkdir()
            (pkg / "fixture.py").write_text("VALUE = 1\n")
            mutants = [mutate.Mutant("fixture", 1, "int:shift", "VALUE = 1", "0",
                                     f"fixture:1:{i}", detail="VALUE = 0")
                       for i in (1, 2)]
            worktrees = []

            def fresh_tree(destination):
                destination.mkdir()
                (destination / "baseline.txt").write_text("pristine")

            def execute(mutant, selected, destination, python, timeout):
                self.assertTrue((destination / "baseline.txt").exists())
                self.assertFalse((destination / "test-generated.json").exists(),
                                 "a previous mutant contaminated this checkout")
                worktrees.append(destination)
                (destination / "test-generated.json").write_text("left by a test")
                mutant.status = "KILLED"
                return mutant

            with patch.object(mutate, "PACKAGE", pkg), \
                 patch.object(mutate, "generate", return_value=mutants), \
                 patch.object(mutate, "covering_tests", return_value=None), \
                 patch.object(mutate, "_fresh_tree", side_effect=fresh_tree), \
                 patch.object(mutate, "run_mutant", side_effect=execute):
                report = mutate.run({"fixture": None}, workers=1, timeout=1,
                                    python=sys.executable,
                                    coverage_json=Path(td) / "missing.json", budget=None)
            self.assertEqual(report["counts"], {"KILLED": 2})
            self.assertEqual(len(set(worktrees)), 2)


if __name__ == "__main__":
    unittest.main()
