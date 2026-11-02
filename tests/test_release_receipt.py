"""Negative controls for the independent FALSICORE evidence receipt gate."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch
from tools import release_receipt as g


class Gate(unittest.TestCase):
    def make(self):
        c = g.ROOT / "tests"
        return {
            "schema": g.SCHEMA,
            "runtime_version": g.__version__,
            "input_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "sources_consistent": True,
            "git_head_sha": "c" * 40,
            "head_consistent": True,
            "measurements": {
                "environment": {"host_role": "UNVERIFIED_EXECUTION_ENVIRONMENT"},
                "mutation_testing": {
                    "changed_line": "NOT_MEASURED_IN_RECEIPT",
                    "whole_package": "NOT_MEASURED_IN_RECEIPT",
                },
                "suite": {"exit": 0, "ran": 900, "failed": 0, "errors": 0, "skipped": 0,
                          "test_files": len(list(c.glob("test_*.py")))},
                "coverage": {"run_exit": 0, "json_exit": 0,
                             "num_statements": 100, "covered_lines": 92,
                             "missing_lines": 8, "num_branches": 40,
                             "covered_branches": 38, "missing_branches": 2},
                "static_analysis": {k: {"exit": 0} for k in g.REQUIRED_STATIC},
                "detection_validity": {"passes": True, "rules_without_positive_scenario": []},
            },
        }

    def defects(self, data):
        with patch.object(g, "input_fingerprint", return_value="a" * 64), \
             patch.object(g, "manifest_fingerprint", return_value="b" * 64), \
             patch.object(g, "repository_head", return_value="c" * 40):
            return g.defects(data)

    def test_valid_shaped_receipt_is_accepted(self):
        self.assertEqual(self.defects(self.make()), [])

    def test_missing_or_wrong_source_attestation_is_rejected(self):
        for key, value in (("input_sha256", "x"), ("manifest_sha256", "y"),
                           ("sources_consistent", False), ("schema", "old")):
            data = self.make()
            data[key] = value
            with self.subTest(key=key):
                self.assertTrue(self.defects(data))

    def test_missing_or_mismatched_git_head_is_rejected(self):
        for name, value in (("git_head_sha", "d" * 40),
                            ("git_head_sha", None),
                            ("head_consistent", False)):
            document = self.make()
            document[name] = value
            with self.subTest(name=name, value=value):
                self.assertIn("exact-git-head-not-verified" if
                              name == "git_head_sha" else
                              "git-head-changed-during-measurement",
                              self.defects(document))
        with patch.object(g, "input_fingerprint", return_value="a" * 64), \
             patch.object(g, "manifest_fingerprint", return_value="b" * 64), \
             patch.object(g, "repository_head", return_value=None):
            self.assertIn("exact-git-head-not-verified", g.defects(self.make()))

    def test_repository_head_rejects_unresolved_or_relative_git_path(self):
        for executable in (None, "git", "./git"):
            with self.subTest(executable=executable), \
                 patch.object(g.shutil, "which", return_value=executable), \
                 patch.object(g.subprocess, "run") as invoke:
                self.assertIsNone(g.repository_head())
                invoke.assert_not_called()

    def test_repository_head_uses_absolute_git_and_validates_output(self):
        with patch.object(g.shutil, "which", return_value="/usr/bin/git"), \
             patch.object(g.subprocess, "run") as invoke:
            invoke.return_value.stdout = "a" * 40 + "\n"
            self.assertEqual(g.repository_head(), "a" * 40)
            self.assertEqual(invoke.call_args.args[0],
                             ["/usr/bin/git", "rev-parse", "--verify", "HEAD"])
            self.assertTrue(invoke.call_args.kwargs["check"])
            invoke.return_value.stdout = "not-a-git-commit\n"
            self.assertIsNone(g.repository_head())
            invoke.side_effect = g.subprocess.TimeoutExpired(
                cmd="/usr/bin/git", timeout=10)
            self.assertIsNone(g.repository_head())

    def test_suite_cannot_claim_pass_with_skips_or_boolean_measurements(self):
        # Previously skipped>0, missing skipped, and bool-valued zero exits
        # could pass because Python considers False == 0 and True an int.
        for field, bad in (("skipped", 1), ("skipped", None),
                           ("skipped", False), ("exit", False),
                           ("ran", True), ("errors", False), ("failed", False)):
            document = self.make()
            document["measurements"]["suite"][field] = bad
            with self.subTest(field=field, bad=bad):
                self.assertIn("suite", self.defects(document))
        missing = self.make()
        del missing["measurements"]["suite"]["skipped"]
        self.assertIn("suite", self.defects(missing))

    def test_static_success_requires_integer_zero_not_boolean_false(self):
        for key in g.REQUIRED_STATIC:
            receipt = self.make()
            receipt["measurements"]["static_analysis"][key]["exit"] = False
            with self.subTest(tool=key):
                self.assertIn("static:" + key, self.defects(receipt))

    def test_mutation_receipt_cannot_launder_historical_counts_or_ci_pass(self):
        # Benign twin: an explicit omission is valid, not a PASS claim.
        self.assertEqual(self.defects(self.make()), [])
        for field, bad in (("changed_line", "PASS"), ("whole_package", "PASS"),
                           ("whole_package", {"killed": 307, "survived": 0})):
            document = self.make()
            document["measurements"]["mutation_testing"][field] = bad
            with self.subTest(field=field, bad=bad):
                self.assertIn("mutation-scope", self.defects(document))
        document = self.make()
        document["measurements"]["mutation_testing"]["external_baseline_0_1_3"] = {
            "mutants": 14675, "killed": 8236, "survived": 6390}
        self.assertIn("mutation-scope", self.defects(document))
        document = self.make()
        del document["measurements"]["mutation_testing"]
        self.assertIn("mutation-scope", self.defects(document))

    def test_execution_environment_is_not_verified_maintainer_host(self):
        self.assertEqual(self.defects(self.make()), [])
        for bad in ("MAINTAINER_HOST", None, True):
            document = self.make()
            document["measurements"]["environment"]["host_role"] = bad
            with self.subTest(bad=bad):
                self.assertIn("environment-host-role", self.defects(document))
        document = self.make()
        document["measurements"].pop("environment")
        self.assertIn("environment-host-role", self.defects(document))

    def test_stale_suite_coverage_and_ancillary_fails_closed(self):
        for mode in ("tests", "coverage", "static", "validity"):
            data = self.make()
            if mode == "tests":
                data["measurements"]["suite"]["ran"] = 0
            if mode == "coverage":
                data["measurements"]["coverage"]["covered_branches"] = 0
            if mode == "static":
                data["measurements"]["static_analysis"]["bandit"]["exit"] = 1
            if mode == "validity":
                data["measurements"]["detection_validity"]["passes"] = False
            with self.subTest(mode=mode):
                self.assertTrue(self.defects(data))

    def test_failing_coverage_command_cannot_be_covered_up_by_stale_json(self):
        for field in ("run_exit", "json_exit"):
            for bad in (None, False, 1):
                with self.subTest(field=field, bad=bad):
                    receipt = self.make()
                    receipt["measurements"]["coverage"][field] = bad
                    self.assertTrue(self.defects(receipt))
            receipt = self.make()
            receipt["measurements"]["coverage"].pop(field)
            self.assertTrue(self.defects(receipt))

    def test_malformed_coverage_is_not_a_measurement(self):
        for bad in (None, {}, {"percent_display": "100"}):
            data = self.make()
            data["measurements"]["coverage"] = bad
            self.assertTrue(self.defects(data))


if __name__ == "__main__":
    unittest.main()
