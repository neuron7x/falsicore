"""Negative controls for the audit-to-task registry completeness checker."""
import copy
import json
import unittest
from pathlib import Path

from check_registry import IDS, SOURCE, TASKS, check, source_digest_ok


class RegistryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = json.loads(SOURCE.read_text(encoding='utf-8'))
        cls.tasks = json.loads(TASKS.read_text(encoding='utf-8'))

    def test_original_inputs(self):
        self.assertEqual(len(IDS), 39)
        self.assertEqual(check(self.source, self.tasks), [])

    def test_source_digest_rejects_altered_bytes(self):
        self.assertTrue(source_digest_ok(SOURCE.read_bytes()))
        self.assertFalse(source_digest_ok(SOURCE.read_bytes() + b' '))

    def test_missing_task_is_rejected(self):
        self.assertTrue(check(self.source, self.tasks[:-1]))

    def test_duplicate_task_is_rejected(self):
        self.assertTrue(check(self.source, self.tasks + [self.tasks[0]]))

    def test_altered_falsifier_is_rejected(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]['falsifier'] = ''
        self.assertTrue(check(self.source, tasks))

    def test_missing_acceptance_is_rejected(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]['acceptance'] = ''
        self.assertTrue(check(self.source, tasks))

    def test_unsubstantiated_execution_claim_is_rejected(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]['state'] = 'PASS'
        self.assertTrue(check(self.source, tasks))

    def test_evidenced_execution_claim_has_required_fields(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0].update(state='PASS', evidence='receipt:example', candidate_sha='a' * 40)
        self.assertEqual(check(self.source, tasks), [])

    def test_invalid_dependency_is_rejected(self):
        tasks = copy.deepcopy(self.tasks)
        tasks[0]['dependencies'] = ['FC-99']
        self.assertTrue(check(self.source, tasks))

    def test_changed_source_or_missing_source_is_rejected(self):
        source = copy.deepcopy(self.source)
        source['findings'][0]['falsifier'] = ''
        self.assertTrue(check(source, self.tasks))
        self.assertTrue(check({}, self.tasks))


if __name__ == '__main__':
    unittest.main()
