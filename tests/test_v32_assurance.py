"""Contract-level adversarial/regression cases for assurance release 3.2."""
from __future__ import annotations

import ast
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import safety, detectors
from tools import code_audit as code


class FdSafeReadTests(unittest.TestCase):
    def test_nested_ancestor_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real = base / "real"
            real.mkdir()
            (real / "secret.txt").write_text("PRIVATE", encoding="utf8")
            (base / "ln").symlink_to(real, target_is_directory=True)
            value, state = safety.safe_read(base / "ln" / "secret.txt")
            self.assertIsNone(value)
            self.assertEqual(state, "SYMLINK_OR_NOT_DIRECTORY")

    def test_parent_regular_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a"
            a.write_text("x", encoding="utf8")
            value, status = safety.safe_read(a / "nested")
            self.assertIsNone(value)
            self.assertEqual(status, "SYMLINK_OR_NOT_DIRECTORY")

    def test_empty_and_binary_and_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a"
            a.write_bytes(b"")
            self.assertEqual(safety.safe_read(a, 0), (b"", "COMPLETED"))
            a.write_bytes(b"abc\x00\xff")
            self.assertEqual(safety.safe_read(a, 5), (b"abc\x00\xff", "COMPLETED"))
            self.assertEqual(safety.safe_read(a, 4), (None, "TOO_LARGE"))

    def test_disallows_unbounded_reads(self):
        with self.assertRaises(ValueError):
            safety.safe_read(Path("/etc/passwd"), 2**30)

    def test_nested_relative_name_does_not_resolve_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "target").write_bytes(b"x")
            (base / "link").symlink_to(base / "target")
            value, status = safety.safe_read(base / "link")
            self.assertIsNone(value)
            self.assertEqual(status, "SYMLINK_OR_NOT_DIRECTORY")


class CodeAuditorContractTests(unittest.TestCase):
    def scan(self, source: str):
        return code.inspect_ast(ast.parse(source), "test.py")

    def test_major_vulnerable_patterns(self):
        sample = '''import subprocess, pickle, tempfile, os, requests
x = eval("1")
subprocess.run("echo hello", shell=True)
os.system("date")
pickle.loads(b"payload")
tempfile.mktemp()
requests.get("https://example.org", verify=False)
subprocess.run(["echo", "x"])
os.chmod("x", 0o777)
from pathlib import Path
Path("x").chmod(0o777)
try:
    foo()
except Exception:
    pass
'''
        findings = self.scan(sample)
        found = {x["rule"] for x in findings}
        self.assertEqual(found, set(code.RULES))
        self.assertEqual(len(findings), len(code.RULES) + 1)

    def test_safely_written_code_not_flagged(self):
        sample = '''import json, subprocess, tempfile
x = json.loads("{}")
subprocess.run(["echo", "x"], shell=False, timeout=5)
with tempfile.TemporaryDirectory() as td:
    pass
'''
        self.assertEqual(self.scan(sample), [])

    def test_dynamic_eval_string_is_not_code(self):
        findings = self.scan("text = 'eval(1)'")
        self.assertFalse(findings)

    def test_ast_output_deterministic(self):
        source = "import os\nos.system('echo hi')\n"
        a = self.scan(source)
        b = self.scan(source)
        self.assertEqual(a, b)
        self.assertTrue(a[0]["id"].startswith("SRC-"))

    def test_collector_excludes_bytecode_and_nonpy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "x.py").write_text("x=1\n", encoding="utf8")
            (root / "secret.txt").write_text("password=abc\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "bad.py").write_text("eval('x')")
            report = code.audit_directory(root)
            self.assertEqual(report["files_parsed"], 1)
            self.assertNotIn("secret", json.dumps(report))
            self.assertEqual(report["collection_errors"], [])

    def test_malformed_file_records_gap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bad.py").write_text("def not valid syntax:\n")
            report = code.audit_directory(root)
            self.assertEqual(report["files_discovered"], 1)
            self.assertEqual(report["files_parsed"], 0)
            self.assertEqual(report["collection_errors"][0]["reason"], "SyntaxError")

    def test_symlink_directory_is_gap_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "link").symlink_to(Path("/tmp"), target_is_directory=True)
            report = code.audit_directory(root)
            self.assertEqual(report["collection_errors"][0]["reason"], "SYMLINK_DIRECTORY_SKIPPED")

    def test_alias_imports_canonicalized(self):
        src = "import subprocess as sp\nfrom os import system as dispatch\nfrom pickle import loads as decode\nsp.run('x', shell=True)\ndispatch('x')\ndecode(b'x')"
        rules = {x["rule"] for x in self.scan(src)}
        self.assertEqual(rules, {"FC-AST-002", "FC-AST-003", "FC-AST-004"})

    def test_narrow_cleanup_exception_not_highlighted(self):
        self.assertEqual(self.scan("try:\n f()\nexcept ProcessLookupError:\n pass"), [])

    def test_alias_tls_disabled(self):
        rules = {x["rule"] for x in self.scan("import requests as rq\nrq.get('https://x', verify=False)")}
        self.assertEqual(rules, {"FC-AST-006"})

    def test_dynamic_shell_false_not_flagged(self):
        self.assertEqual(self.scan('import subprocess\nsubprocess.run(["id"], shell=False, timeout=3)'), [])

    def test_no_import_or_execution_of_subject(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "explode.py").write_text("raise RuntimeError('executed!')\n")
            report = code.audit_directory(root)
            self.assertEqual(report["files_parsed"], 1)
            self.assertEqual(report["findings"], [])

    def test_missing_directory_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                code.audit_directory(Path(td)/"missing")

    def test_false_positive_label_explicit(self):
        r = self.scan('eval("x")')[0]
        self.assertEqual(r["confidence"], "PATTERN_ONLY")
        self.assertTrue(r["requires_review"])


class SeededInputRobustness(unittest.TestCase):
    def test_parsers_do_not_raise_on_strange_bounded_inputs(self):
        import random
        rand = random.Random(0x32F0C0)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.%/:*[]<>\\x00+-?\t\n"
        for _ in range(500):
            s = "".join(rand.choices(alphabet, k=rand.randint(0, 180)))
            self.assertIsInstance(detectors.grants_host_access(s, ("instagram.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com")), bool)
            self.assertIsInstance(detectors.endpoint_class(s), str)
            self.assertIsInstance(detectors.parse_ss(s), list)
            self.assertIsInstance(detectors.suspect_command(s), list)

    def test_known_host_boundary_negative_set(self):
        for host in ["fakeinstagram.com", "notinstagram.com", "instagram.com.attacker.example", "evil-instagram.com", "instagrarn.com", "www.instagram.com.evil.example"]:
            self.assertFalse(detectors.grants_host_access("https://"+host+"/*", ("instagram.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com")), host)

    def test_known_host_boundary_positive_set(self):
        for host in ["instagram.com", "www.instagram.com", "graph.instagram.com", "*.instagram.com"]:
            self.assertTrue(detectors.grants_host_access("https://"+host+"/*", ("instagram.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com")), host)


if __name__ == "__main__":
    unittest.main()


class ProcessLifetimeTests(unittest.TestCase):
    def test_command_timeout_kills_process_group_after_parent_exits(self):
        """Child exits first; grandchild retains inherited stdout. A timed-out
        command must kill the group even if direct parent's poll() is non-None.
        """
        import sys
        script = ("import subprocess, sys\n"
                  "subprocess.Popen([sys.executable, '-I', '-c', 'import time;time.sleep(15)'])\n")
        original_killpg = os.killpg
        with patch.object(safety, "checked_executable", return_value=sys.executable), \
             patch.object(safety.os, "killpg", wraps=original_killpg) as killed:
            result = safety.run_command("uname", ["-I", "-c", script], timeout=0.3, limit=512)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error"], "timeout")
        self.assertTrue(killed.called, "orphan-grandchild process group not killed")

    def test_bounded_output_triggers_group_cleanup(self):
        import sys
        with patch.object(safety, "checked_executable", return_value=sys.executable), \
             patch.object(safety.os, "killpg", wraps=os.killpg) as killed:
            result = safety.run_command("uname", ["-I", "-c", "import sys;sys.stdout.write('x'*8000);sys.stdout.flush()"],
                                        timeout=2, limit=64)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertLessEqual(len(result["stdout"]), 64)
        self.assertTrue(killed.called)


class StandardOSReleaseFallbackTests(unittest.TestCase):
    def test_vendor_os_release_fallback_preserves_metadata(self):
        # A symlink is NOT followed. A separately named fixed vendor file is read.
        import pwd
        from falsicore.collectors import Audit
        from unittest.mock import patch
        uid = 1000 if os.geteuid() == 0 else os.geteuid()
        if os.geteuid() == 0:
            # Stub minimal target-user record so the constructor has no reliance
            # on the user's actual Ubuntu accounts.
            rec = type('Rec', (), {'pw_uid': 1000, 'pw_dir': '/nonexistent'})()
            with patch('falsicore.collectors.pwd.getpwnam', return_value=rec):
                audit = Audit('system', target_user='test-person')
        else:
            audit = Audit('user')
        original = safety.safe_read
        def simulated(path, limit=131072):
            if str(path) == '/etc/os-release':
                return None, 'SYMLINK_OR_NOT_DIRECTORY'
            if str(path) == '/usr/lib/os-release':
                return b'ID=ubuntu\nVERSION_ID="24.04"\n', 'COMPLETED'
            return original(path, limit)
        def fake_command(tool, args, *other, **kwargs):
            return {'status': 'COMPLETED', 'stdout': '6.8.0-test\n', 'exit': 0,
                    'elapsed_ms': 0, 'truncated': False, 'error': ''}
        with patch('falsicore.collectors.safe_read', side_effect=simulated), patch.object(audit, 'command', side_effect=fake_command):
            audit.environment()
        self.assertEqual(audit.stats['host']['os_release']['ID'], 'ubuntu')
        self.assertEqual(audit.stats['host']['os_release_source'], '/usr/lib/os-release')
        self.assertEqual(audit.coverage[-1]['status'], 'COMPLETED')


class IncidentTimestampCoverageTests(unittest.TestCase):
    def test_invalid_journal_timestamp_requires_partial_coverage(self):
        from falsicore.collectors import Audit
        if os.geteuid() == 0:
            rec = type('Rec', (), {'pw_uid': 1000, 'pw_dir': '/nonexistent'})()
            with patch('falsicore.collectors.pwd.getpwnam', return_value=rec):
                audit = Audit('system', target_user='test-person', incident_at='2026-10-27T12:00:00+02:00')
        else:
            audit = Audit('user', incident_at='2026-10-27T12:00:00+02:00')
        line = json.dumps({'MESSAGE': 'Accepted password for user', '__REALTIME_TIMESTAMP': 'not-a-timestamp'})
        reply = {'status':'COMPLETED','stdout':line+'\n','exit':0,'elapsed_ms':0,'truncated':False,'error':''}
        with patch.object(audit,'command',return_value=reply):
            audit.auth()
        self.assertEqual(audit.stats['auth']['invalid_incident_timestamps'], 1)
        self.assertEqual(audit.coverage[-1]['status'], 'PARTIAL')
        self.assertEqual(audit.stats['auth']['event_counts']['SSH_ACCEPTED'], 1)


class PackagingAllowlistTests(unittest.TestCase):
    def test_unexpected_local_json_is_not_permitted(self):
        from tools.build_release import allowed_release_path
        self.assertFalse(allowed_release_path(Path('private_index.json')))
        self.assertFalse(allowed_release_path(Path('source-audit-local.json')))
        self.assertFalse(allowed_release_path(Path('docs/private_account_secrets.txt')))
        self.assertFalse(allowed_release_path(Path('tests/dump.zip')))
        self.assertTrue(allowed_release_path(Path('tools/code_audit.py')))
        self.assertTrue(allowed_release_path(Path('.github/workflows/verify.yml')))

    def test_build_rejects_actual_unexpected_payload(self):
        from tools import build_release
        # Never modify the real source checkout; test a private synthetic tree.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "falsicore-0.1.0"
            root.mkdir()
            (root / "README.md").write_text("fixture")
            (root / "untracked_private_account_data.json").write_text("SECRET_DO_NOT_PACK")
            with patch.object(build_release, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Unexpected release payload"):
                    build_release.source_files()


class VersionedBaselineTests(unittest.TestCase):
    def test_tool_version_change_rejects_baseline(self):
        from falsicore.report import comparable
        base = dict(schema='falsicore.summary.v3', scope='user', profile='standard',
                    target_uid=1000, host_ref='stable-host', tool_version='3.1.0-rc1')
        now = dict(base, tool_version='3.2.0')
        self.assertFalse(comparable(base, now))
        self.assertTrue(comparable(now, dict(now)))
