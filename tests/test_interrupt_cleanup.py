"""Interrupts are cancellation, not successful partial subprocess completion."""
import signal
import sys
import unittest
from unittest.mock import patch
from falsicore import safety


class InterruptCleanupContracts(unittest.TestCase):
    def test_keyboard_interrupt_terminates_owned_child_group(self):
        original_killpg = safety.os.killpg
        with patch.object(safety, "checked_executable", return_value=sys.executable), \
             patch("selectors.EpollSelector.select", side_effect=KeyboardInterrupt), \
             patch.object(safety.os, "killpg", wraps=original_killpg) as killed:
            with self.assertRaises(KeyboardInterrupt):
                safety.run_command("uname", ["-I", "-c", "import time;time.sleep(20)"], timeout=1)
            killed.assert_called_once()
            self.assertEqual(killed.call_args.args[1], signal.SIGKILL)
