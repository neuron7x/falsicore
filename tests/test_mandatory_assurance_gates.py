"""Fail-closed CI policy checks: critical evidence cannot be an optional green badge.

These tests pin workflow source text rather than pretending to prove GitHub
administrator settings. Runtime CI still has to establish the actual result.
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MandatoryAssuranceGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # .github is automation metadata, excluded intentionally from the
        # portable app's source archive. Its self-test cannot inspect it.
        # Never silently skip missing workflows in a real GitHub checkout.
        if not (ROOT / ".github").is_dir():
            if (ROOT / ".git").exists():
                raise AssertionError("Repository checkout lost .github workflows")
            raise unittest.SkipTest(
                "Repository CI policy is validated in source checkout; "
                "portable app does not ship .github workflows")

    def test_required_static_analysis_fails_without_source_bound_evidence(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        section = workflow.split("  static-analysis:\n", 1)[1]
        self.assertIn("needs: evidence", section)
        self.assertIn("if: " + "$" + "{{ always() }}", section)
        self.assertIn("needs.evidence.result", section)
        self.assertIn('test "$EVIDENCE_JOB_RESULT" = success', section)
        self.assertIn("Source manifest is current and intact", workflow)
        self.assertIn("Mutants on changed lines must all be killed", workflow)

    def test_whole_package_mutation_does_not_waive_survivors_or_hide_red_results(self):
        workflow = (ROOT / ".github/workflows/mutation.yml").read_text()
        self.assertIn("tools/mutate.py --all", workflow)
        self.assertNotIn("--allow-survivors", workflow)
        self.assertIn("--json mutation.json --markdown mutation.md", workflow)
        artifact = workflow.split("actions/upload-artifact@", 1)[1]
        self.assertIn("if: always()", artifact)
        self.assertIn("if-no-files-found: error", artifact)

    def test_source_act_and_registry_falsifiers_run_before_artifact_build(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        for name, text in (("verify", workflow), ("release", release)):
            with self.subTest(name=name):
                self.assertIn("sha256sum -c AUDIT_CHECKSUMS.txt", text)
                self.assertIn("python assurance/check_registry.py", text)
                self.assertIn("python -m unittest discover -s assurance -q", text)

    def test_tagged_release_rejects_unsigned_or_mismatched_release(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("Require a verified annotated release tag", workflow)
        self.assertIn('.verification.verified == true', workflow)
        self.assertIn('.object.type == "commit"', workflow)
        self.assertIn('git rev-parse HEAD', workflow)
        self.assertIn('gh release create "$GITHUB_REF_NAME"', workflow)
        self.assertIn('gh api "repos/$GH_REPO/branches/main"', workflow)
        self.assertIn('test "$main_sha" = "$(git rev-parse HEAD)"', workflow)
        self.assertIn('test "$(gh api "repos/$GH_REPO/branches/main" --jq', workflow)
        self.assertIn('test "$(printf', workflow)


if __name__ == "__main__":
    unittest.main()
