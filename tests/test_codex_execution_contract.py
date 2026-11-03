"""FALSICORE PR #19 Codex handoff: canonical task coverage and safe packaging.

These are structural controls; they prove that the agent sees a complete
contract, NOT that the 39 engineering or external assurance tasks are done.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tools import build_release

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "AGENTS.md"
CONTRACT = ROOT / "docs/CODEX_EXECUTION_CONTRACT.md"
REGISTER = ROOT / "docs/verification/tasks.json"


class CodexHandoffContract(unittest.TestCase):
    def test_root_instruction_and_explicit_source_allowlist(self):
        self.assertTrue(AGENTS.is_file())
        self.assertTrue(CONTRACT.is_file())
        self.assertTrue(build_release.allowed_release_path(Path("AGENTS.md")))
        self.assertTrue(build_release.allowed_release_path(
            Path("docs/CODEX_EXECUTION_CONTRACT.md")))
        self.assertFalse(build_release.allowed_release_path(
            Path("AGENTS.override.md")))

    def test_all_39_canonical_finding_ids_are_visible(self):
        tasks = json.loads(REGISTER.read_text(encoding="utf-8"))
        self.assertEqual(len(tasks), 39)
        expected = {f"FC-{n:02d}" for n in range(1, 40)}
        self.assertEqual({task["id"] for task in tasks}, expected)
        document = CONTRACT.read_text(encoding="utf-8")
        rows = set(re.findall(r"^\| (FC-\d\d) \|", document, re.M))
        self.assertEqual(rows, expected)
        self.assertIn("docs/verification/tasks.json", document)
        self.assertIn("docs/VERIFICATION_PROGRAM.md", document)

    def test_no_immediate_merge_or_fabricated_certification(self):
        root = AGENTS.read_text(encoding="utf-8")
        instructions = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("owner alone", root.lower())
        self.assertIn("Never merge", root)
        self.assertIn("owner alone", instructions.lower())
        self.assertIn("Codex has NO permission to merge", instructions)
        self.assertIn("MERGE HOLD", root)
        self.assertIn("PENDING_POST_MERGE", root)
        self.assertIn("PENDING_POST_MERGE", instructions)
        self.assertIn("G0–G8", instructions)
        for reference in (
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
            "https://baseline.openssf.org/versions/2026-08-28",
            "https://slsa.dev/spec/v1.2/",
            "https://docs.github.com/en/actions/concepts/security/artifact-attestations",
        ):
            with self.subTest(reference=reference):
                self.assertIn(reference, instructions)

    def test_source_manifest_includes_both_agent_contracts(self):
        manifest = build_release.current_manifest().decode("utf-8")
        self.assertIn("  AGENTS.md\n", manifest)
        self.assertIn("  docs/CODEX_EXECUTION_CONTRACT.md\n", manifest)


if __name__ == "__main__":
    unittest.main()
