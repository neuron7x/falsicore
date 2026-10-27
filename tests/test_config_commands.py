import unittest
from falsicore.config_commands import cron_commands, desktop_commands
from falsicore.detectors import suspect_command


class ConfigCommandContracts(unittest.TestCase):
    def test_user_schedule(self):
        self.assertEqual(cron_commands("*/5 * * * * bash /tmp/a"), "bash /tmp/a")

    def test_system_schedule(self):
        self.assertEqual(cron_commands("*/5 * * * * root bash /tmp/a", system=True), "bash /tmp/a")

    def test_named_schedule(self):
        self.assertEqual(cron_commands("0 9 * JAN MON bash /tmp/a"), "bash /tmp/a")

    def test_reboot_system(self):
        self.assertEqual(cron_commands("@reboot user /tmp/run", system=True), "/tmp/run")

    def test_reboot_user(self):
        self.assertEqual(cron_commands("@reboot /tmp/run"), "/tmp/run")

    def test_script_preserved(self):
        self.assertEqual(cron_commands("#!/bin/sh\nsource /tmp/a"), "source /tmp/a")

    def test_comment_excluded(self):
        self.assertEqual(cron_commands("# * * * * * bash /tmp/a"), "")

    def test_cron_literal_execution_detected(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", suspect_command(cron_commands("* * * * * bash /tmp/a")))

    def test_cron_data_not_execution(self):
        self.assertEqual(suspect_command(cron_commands("* * * * * echo /tmp/a")), [])

    def test_desktop_name_is_not_command(self):
        self.assertEqual(desktop_commands("[Desktop Entry]\nName=bash /tmp/a\nExec=/usr/bin/true"), "/usr/bin/true")

    def test_desktop_literal_command_detected(self):
        self.assertIn("TEMP_PATH_IN_EXECUTION", suspect_command(desktop_commands("Exec=/tmp/a %U")))

    def test_desktop_data_argument_benign(self):
        self.assertEqual(suspect_command(desktop_commands("Exec=/usr/bin/app --cache=/tmp/a")), [])
