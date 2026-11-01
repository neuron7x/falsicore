"""The mutation tool itself: operators, selection, diff parsing, annotations.

End-to-end execution (tree copy + subprocess) is exercised by the CI job
`mutation-diff`; here the pure parts are pinned so the tool cannot silently
stop generating a class of mutants or start skipping annotated lines.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

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
            if m.status != "ANNOTATED":
                ast.parse(m.detail)   # the mutated module is valid Python
                self.assertNotEqual(m.detail, SNIPPET)

    def test_line_restriction_and_identities_are_unique(self):
        mutants = mutate.generate("snippet", SNIPPET, lines={7})
        self.assertTrue(mutants)
        self.assertTrue(all(m.line == 7 for m in mutants))
        ids = [m.mutant_id for m in mutate.generate("snippet", SNIPPET)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_annotation_requires_a_reason_and_marks_the_mutant(self):
        mutants = mutate.generate("snippet", SNIPPET, lines={10})
        self.assertTrue(mutants)
        self.assertTrue(all(m.status == "ANNOTATED" for m in mutants))
        self.assertEqual(mutants[0].detail, "documentation example")
        bare = mutate.generate("s", "x = 1  # no mutate:\n")
        self.assertTrue(all(m.status != "ANNOTATED" for m in bare))

    def test_strings_are_never_mutated(self):
        mutants = mutate.generate("s", 'MESSAGE = "do not touch"\n')
        self.assertEqual(mutants, [])

    def test_mutated_source_differs_exactly_at_the_site(self):
        mutants = [m for m in mutate.generate("s", "def f(a):\n    return a < 3\n") if m.operator.startswith("compare")]
        self.assertEqual(len(mutants), 1)
        self.assertIn("a <= 3", mutants[0].detail)


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


if __name__ == "__main__":
    unittest.main()
