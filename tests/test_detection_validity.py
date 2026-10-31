"""Claim C8: every rule detects the artifact shape it targets and stays silent on
its benign twin, on a hermetic fixture host whose unplanted state reaches
NO_COMPROMISE_INDICATORS_OBSERVED. `docs/DETECTION_VALIDITY.json` must be the
current output of the harness, so the published table is bound to the code.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools import validity

ROOT = Path(__file__).resolve().parents[1]


class DetectionValidity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = validity.evaluate()

    def test_unplanted_host_is_not_inconclusive(self):
        for clean in self.result["clean_host"]:
            self.assertEqual(clean["outcome"], "NO_COMPROMISE_INDICATORS_OBSERVED", clean)
            self.assertEqual(clean["findings"], [], clean)
            self.assertEqual(clean["incomplete_essential"], [], clean)

    def test_every_planted_artifact_is_detected(self):
        self.assertEqual(self.result["missed_positives"], [])

    def test_no_benign_twin_raises_an_alarm(self):
        self.assertEqual(self.result["false_alarms"], [])

    def test_every_rule_has_a_positive_scenario(self):
        self.assertEqual(self.result["rules_without_positive_scenario"], [])

    def test_known_gaps_are_still_gaps_or_the_scenario_is_stale(self):
        # A gap that closes is good news, but the scenario must then be
        # promoted to a positive so the table stops calling it a gap.
        closed = [r["name"] for r in self.result["scenarios"] if r["kind"] == "known_gap" and r["detected"]]
        self.assertEqual(closed, [], "known gap now detected: promote the scenario")

    def test_probe_policy_is_enforced_inside_the_harness(self):
        host_dir = ROOT / "tests"  # any existing directory; nothing is written
        host = validity.FixtureHost.__new__(validity.FixtureHost)
        host.commands_seen, host.outputs = [], {}
        with self.assertRaises(PermissionError):
            host.fake_command("systemctl", ["disable", "ssh"])
        with self.assertRaises(PermissionError):
            host.fake_command("dpkg", ["--purge", "sudo"])
        self.assertTrue(host_dir.is_dir())

    def test_committed_result_is_current(self):
        committed = json.loads((ROOT / "docs" / "DETECTION_VALIDITY.json").read_text())
        self.assertEqual(committed, self.result, "run: python3 tools/validity.py --write")

    def test_result_declares_its_limits(self):
        self.assertIn("real malware", self.result["does_not_measure"])
        self.assertTrue(self.result["passes"])


if __name__ == "__main__":
    unittest.main()
