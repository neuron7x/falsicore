import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from falsicore.collectors import Audit
from falsicore import detectors as d

class SystemScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        user=SimpleNamespace(pw_uid=12345,pw_dir=str(self.home))
        with patch("falsicore.collectors.pwd.getpwnam",return_value=user), \
             patch("falsicore.collectors.os.geteuid",return_value=0):
            self.a=Audit("system",target_user="fixture",profile="deep")

    def response(self, status="COMPLETED", text="", exit=0):
        return {"status":status,"stdout":text,"exit":exit,"elapsed_ms":0,"truncated":False,"error":""}

    def test_system_requires_user(self):
        # The same assertion must hold on developer machines and non-root CI.
        with patch("falsicore.collectors.os.geteuid", return_value=0):
            with self.assertRaises(ValueError):
                Audit("system")

    def test_reject_root_target(self):
        with patch("falsicore.collectors.os.geteuid", return_value=0), \
             patch("falsicore.collectors.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=0,pw_dir="/root")):
            with self.assertRaises(ValueError):
                Audit("system", target_user="root")

    def test_reject_unsupported_scope(self):
        with self.assertRaises(ValueError):
            Audit("everything",target_user="fixture")

    def test_system_package_verify_clean(self):
        self.a._files=lambda *args,**k:([],False)
        self.a.command=lambda tool,args,**kw:self.response("COMPLETED")
        self.a.packages()
        self.assertEqual(self.a.coverage[-1]["status"],"COMPLETED")
        self.assertEqual(self.a.stats["package_integrity"]["changed_file_records"],0)

    def test_system_package_verify_modified(self):
        self.a._files=lambda *args,**k:([],False)
        self.a.command=lambda tool,args,**kw:self.response("FAILED","??5??????  /usr/bin/sample\n",1)
        self.a.packages()
        self.assertIn("DPKG_FILE_DRIFT", {f["rule"] for f in self.a.findings})
        self.assertEqual(self.a.stats["package_integrity"]["changed_file_records"],1)
        self.assertEqual(self.a.findings[0]["kind"],"CONTEXT")

    def test_system_package_verify_unavailable(self):
        self.a._files=lambda *args,**k:([],False)
        self.a.command=lambda *a,**k:self.response("UNAVAILABLE", "",None)
        self.a.packages()
        self.assertEqual(self.a.coverage[-1]["status"],"PARTIAL")

    def test_system_kernel_secureboot(self):
        self.a.command=lambda tool,args,**kw:self.response("COMPLETED","SecureBoot enabled\n")
        self.a.kernel()
        self.assertEqual(self.a.stats["kernel"]["secure_boot_status"],"ENABLED")

    def test_user_root_refused(self):
        with patch("falsicore.collectors.os.geteuid", return_value=0):
            with self.assertRaises(PermissionError):
                Audit("user",target_user="fixture")

    def test_system_nonroot_refused(self):
        with patch("falsicore.collectors.os.geteuid",return_value=12345):
            with self.assertRaises(PermissionError):
                Audit("system",target_user="fixture")

    def test_sudoers_nopasswd_fixture(self):
        file=self.home/"sudoers.fixture"
        file.write_text("fixture ALL=(ALL) NOPASSWD: /usr/bin/id\n")
        def files(bases,**kw):
            if Path("/etc/sudoers.d") in bases:
                return [file],False
            return [],False
        self.a._files=files
        self.a.command=lambda tool,args,**kw:self.response("UNAVAILABLE")
        self.a.persistence()
        self.assertIn("SUDO_NOPASSWD_RULE",{f["rule"] for f in self.a.findings})
        self.assertEqual(self.a.findings[0]["kind"],"HARDENING")

    def test_systemd_symlink_fixture(self):
        folder=self.home/".config/systemd/user"
        folder.mkdir(parents=True)
        (folder/"evil.service").symlink_to("/tmp/evil.service")
        self.a._files=lambda *args,**k:([],False)
        self.a.command=lambda *args,**kw:self.response("UNAVAILABLE")
        self.a.persistence()
        self.assertIn("SYSTEMD_SYMLINK_TO_TEMP",{x["rule"] for x in self.a.findings})

    def test_dynamic_loader_status_nonassertion(self):
        self.a._files=lambda *args,**k:([],False)
        self.a.command=lambda *args,**kw:self.response("UNAVAILABLE")
        self.a.persistence()
        self.assertNotIn("CONFIRMED_COMPROMISE",json.dumps(self.a.findings))
