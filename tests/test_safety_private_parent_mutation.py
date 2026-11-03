"""Direct negative controls for private output-parent type and ownership checks.

The metadata injection models a post-mkdir path swap; it does not modify
host ownership or elevate privileges. A valid private directory is the twin.
"""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore.safety import require_private_parent


class PrivateParentMetadataGuards(unittest.TestCase):
    def _check_with_post_mkdir_metadata(self, directory: Path, *, mode=None, uid=None) -> None:
        original_lstat = Path.lstat
        seen_target = []

        def substituted_lstat(path: Path, *args, **kwargs):
            observed = original_lstat(path, *args, **kwargs)
            if path != directory:
                return observed
            seen_target.append(True)
            fields = list(observed[:10])
            if mode is not None:
                fields[0] = mode
            if uid is not None:
                fields[4] = uid
            return os.stat_result(fields)

        with patch.object(Path, "lstat", autospec=True, side_effect=substituted_lstat):
            require_private_parent(directory)
        self.assertTrue(seen_target, "the intended output path must be observed")

    def test_private_0700_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "runs"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            require_private_parent(directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_existing_shared_0755_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "runs"
            directory.mkdir()
            directory.chmod(0o755)
            with self.assertRaises(PermissionError):
                require_private_parent(directory)

    def test_regular_file_metadata_with_correct_owner_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "runs"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            # A TOCTOU replacement has a non-directory type, but matching UID.
            with self.assertRaises(PermissionError):
                self._check_with_post_mkdir_metadata(directory, mode=stat.S_IFREG | 0o700)

    def test_private_directory_metadata_with_foreign_owner_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "runs"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            # A swapped inode may be a directory while its UID is foreign.
            with self.assertRaises(PermissionError):
                self._check_with_post_mkdir_metadata(directory, uid=os.geteuid() + 1)


if __name__ == "__main__":
    unittest.main()
