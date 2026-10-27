"""systemctl --user needs a vetted runtime dir; probes keep the minimal env."""
from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import monitor, safety


class UserBusEnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.runtime = self.base / str(os.geteuid())

    def tearDown(self):
        self.tmp.cleanup()

    def test_private_runtime_dir_with_bus(self):
        self.runtime.mkdir(mode=0o700)
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(self.runtime / "bus"))
        self.addCleanup(sock.close)
        env = monitor.user_bus_env(self.base)
        self.assertEqual(env["XDG_RUNTIME_DIR"], str(self.runtime))
        self.assertEqual(env["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={self.runtime / 'bus'}")
        self.assertEqual(env["PATH"], safety.minimal_env()["PATH"])

    def test_shared_runtime_dir_refused(self):
        self.runtime.mkdir(mode=0o755)
        os.chmod(self.runtime, 0o755)
        with self.assertRaises(PermissionError):
            monitor.user_bus_env(self.base)

    def test_symlinked_runtime_dir_refused(self):
        real = self.base / "elsewhere"
        real.mkdir(mode=0o700)
        self.runtime.symlink_to(real)
        with self.assertRaises(PermissionError):
            monitor.user_bus_env(self.base)

    def test_missing_runtime_dir_stops_before_unit_write(self):
        home = self.base / "home"
        with patch.object(monitor, "user_bus_env", side_effect=RuntimeError("no session")), \
             patch.object(monitor.os, "geteuid", return_value=1000):
            with self.assertRaises(RuntimeError):
                monitor.enable(Path("/opt/falsicore"), home)
        self.assertFalse((home / ".config/systemd/user").exists())

    def test_probe_env_stays_minimal(self):
        self.assertNotIn("XDG_RUNTIME_DIR", safety.minimal_env())
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", safety.minimal_env())


if __name__ == "__main__":
    unittest.main()
