"""Actual persistence collector consumes new rules and keeps source text private."""
import unittest
from pathlib import Path
from unittest.mock import patch
from falsicore.collectors import Audit


class ShellCollectorEndToEnd(unittest.TestCase):
    def collect(self, text):
        with patch('falsicore.collectors.os.geteuid', return_value=1001), \
             patch('falsicore.collectors.os.getuid', return_value=1001):
            audit = Audit('user', target_user='nobody')
        audit.home = Path('/fixture-user')
        def read(path, *args):
            return (text.encode(), 'COMPLETED') if path == audit.home / '.bashrc' else (None, 'ABSENT')
        response = {'status':'FAILED', 'stdout':'no crontab for user', 'exit':1,
                    'elapsed_ms':0, 'truncated':False, 'error':''}
        with patch('falsicore.collectors.safe_read', side_effect=read), \
             patch.object(audit, '_files', return_value=([], False)), \
             patch.object(audit, 'command', return_value=response), \
             patch.object(Path, 'is_dir', return_value=False):
            audit.persistence()
        return audit

    def test_observed_cross_line_structure_no_longer_flags(self):
        # Synthetic structure only: the real private line 78 was not supplied.
        text = '# bash initialization\n' + '\n' * 76 + 'export CACHE=/tmp/cache\npython3 --version\n'
        audit = self.collect(text)
        self.assertFalse(any(f['rule'] == 'SUSPICIOUS_SHELL_INIT' for f in audit.findings))
        self.assertEqual(len(audit.coverage), 1)

    def test_direct_execution_has_location_but_no_source_contents(self):
        audit = self.collect('# comment\nsource /tmp/NEVER_EXPORT_THIS\n')
        found = [f for f in audit.findings if f['rule']=='SUSPICIOUS_SHELL_INIT']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['evidence']['file_name'], '.bashrc')
        self.assertEqual(found[0]['evidence']['locations'][0]['line'], 2)
        self.assertNotIn('NEVER_EXPORT_THIS', str(found))

    def test_indirect_execution_is_unknown_not_clear(self):
        audit = self.collect('bash "$UNKNOWN_SCRIPT"\n')
        self.assertTrue(audit.stats['shell_analysis_limits'])
        self.assertEqual(audit.coverage[0]['status'], 'PARTIAL')
