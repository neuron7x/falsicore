"""Regress portable CLI failure statuses; cancellation must never look successful.

The whole-package mutant bundle:157:3:int:shift rewrites KeyboardInterrupt's
exit 130 to 0. Inject only exceptions at the bundle-validation boundary;
no host scan, mutable path or external file is used.
"""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from zipfile import BadZipFile

from falsicore import bundle


class BundleMainExitStatus(unittest.TestCase):
    def _run(self, *, value: dict[str, bytes] | None = None, error: BaseException | None = None):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(bundle, "read_verified_bundle", return_value=value, side_effect=error):
            with redirect_stdout(out), redirect_stderr(err):
                result = bundle.main(["verify-app"])
        return result, out.getvalue(), err.getvalue()

    def test_keyboard_interrupt_is_failure_not_success(self):
        code, stdout, stderr = self._run(error=KeyboardInterrupt())
        self.assertEqual(code, 130)
        self.assertNotIn("VERIFIED", stdout)
        self.assertIn("Скасовано", stderr)

    def test_valid_bundle_verification_succeeds_without_signature_claim(self):
        code, stdout, stderr = self._run(value={})
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED: bundle file set", stdout)
        self.assertIn("Not a digital signature", stdout)
        self.assertEqual(stderr, "")

    def test_corrupt_bundle_error_is_not_success(self):
        code, stdout, stderr = self._run(error=BadZipFile("synthetic bad zip"))
        self.assertEqual(code, 2)
        self.assertNotIn("VERIFIED", stdout)
        self.assertIn("FALSICORE ERROR: BadZipFile", stderr)

    def test_invalid_bundle_schema_error_is_not_success(self):
        code, stdout, stderr = self._run(error=ValueError("synthetic invalid schema"))
        self.assertEqual(code, 2)
        self.assertNotIn("VERIFIED", stdout)
        self.assertIn("FALSICORE ERROR: ValueError", stderr)


if __name__ == "__main__":
    unittest.main()
