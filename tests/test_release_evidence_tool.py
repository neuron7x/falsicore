"""`tools/release_evidence.py --check`: the committed evidence must name this version and a green suite."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import __version__
from tools import release_evidence


class ReleaseEvidenceCheck(unittest.TestCase):
    def check_with(self, document: dict) -> int:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "RELEASE_EVIDENCE.json"
            path.write_text(json.dumps(document))
            with patch.object(release_evidence, "OUT", path):
                return release_evidence.main(["--check"])

    def test_historical_green_file_cannot_certify_current_source(self):
        self.assertEqual(self.check_with({"schema": release_evidence.SCHEMA, "version": __version__, "suite": {"exit": 0}}), 1)

    def test_stale_version_or_schema_fails(self):
        self.assertEqual(self.check_with({"schema": release_evidence.SCHEMA, "version": "0.0.1", "suite": {"exit": 0}}), 1)
        self.assertEqual(self.check_with({"schema": "old", "version": __version__, "suite": {"exit": 0}}), 1)

    def test_red_suite_fails(self):
        self.assertEqual(self.check_with({"schema": release_evidence.SCHEMA, "version": __version__, "suite": {"exit": 1}}), 1)
        self.assertEqual(self.check_with({"schema": release_evidence.SCHEMA, "version": __version__}), 1)

    def test_committed_file_is_historical_only(self):
        self.assertEqual(release_evidence.main(["--check"]), 1)


if __name__ == "__main__":
    unittest.main()
