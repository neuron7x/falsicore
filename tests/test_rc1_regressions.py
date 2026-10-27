"""Independently reconstructed defects, then fixed with adversarial fixtures."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from falsicore.detectors import extension_assessment, grants_instagram_access
from falsicore.collectors import Audit, _extension_version_key


class BrowserHostnameAdversarialTests(unittest.TestCase):
    def test_false_instagram_substring_domain(self):
        for host in ("fakeinstagram.com", "instagram.com.evil.example", "www.instagram.com.evil.example"):
            with self.subTest(host=host):
                self.assertFalse(grants_instagram_access(f"https://{host}/*"))
                self.assertFalse(extension_assessment({"permissions": ["cookies"],
                    "host_permissions": [f"https://{host}/*"]})["instagram_access_potential"])

    def test_real_instagram_apex_and_subdomain(self):
        for p in ("https://instagram.com/*", "https://www.instagram.com/*",
                  "*://*.instagram.com/*", "<all_urls>", "*://*/*"):
            with self.subTest(pattern=p):
                self.assertTrue(grants_instagram_access(p))

    def test_non_instagram_script_is_not_instagram_exposure(self):
        manifest = {"content_scripts": [{"matches": ["https://www.instagram.com.evil.example/*"]}]}
        self.assertFalse(extension_assessment(manifest)["content_script_instagram_access"])
        manifest["content_scripts"][0]["matches"] = ["https://www.instagram.com/*"]
        self.assertTrue(extension_assessment(manifest)["content_script_instagram_access"])


class VersionAndVendorUnitsTests(unittest.TestCase):
    def test_version_10_newer_than_9(self):
        self.assertGreater(_extension_version_key(Path("10.0.0_0")), _extension_version_key(Path("9.99.9_0")))

    def test_active_newer_extension_not_older_stale_version(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            user = SimpleNamespace(pw_uid=24680, pw_dir=str(root))
            with patch("falsicore.collectors.pwd.getpwnam", return_value=user), \
                 patch("falsicore.collectors.os.geteuid", return_value=24680):
                audit = Audit("user", target_user="fixture")
            old = root / ".config/chromium/Default/Extensions/abce/9.99.0/manifest.json"
            new = root / ".config/chromium/Default/Extensions/abce/10.0.0/manifest.json"
            old.parent.mkdir(parents=True)
            new.parent.mkdir(parents=True)
            old.write_text(json.dumps({"permissions":["cookies"],"host_permissions":["https://instagram.com/*"]}))
            new.write_text(json.dumps({"permissions":["storage"]}))
            n, _, incomplete = audit._scan_chromium("chromium", root / ".config/chromium")
            self.assertEqual(n, 1)
            self.assertFalse(incomplete)
            self.assertFalse(any(f["rule"] == "POWERFUL_BROWSER_EXTENSION" for f in audit.findings))

    def test_vendor_systemd_units_in_inventory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            user = SimpleNamespace(pw_uid=24680, pw_dir=str(root))
            with patch("falsicore.collectors.pwd.getpwnam", return_value=user), \
                 patch("falsicore.collectors.os.geteuid", return_value=24680):
                audit = Audit("user", target_user="fixture")
            seen = []
            def fake_files(bases, **kwargs):
                if kwargs.get('extensions') == {'.service','.timer','.socket'}:
                    seen.extend(str(b) for b in bases)
                return [], False
            audit._files = fake_files
            audit.command = lambda *args, **kwargs: {"status":"FAILED", "stdout":"no crontab for fixture", "exit": 1, "error":""}
            audit.persistence()
            # Installed OS contains /usr/lib/systemd/system as a regular folder.
            self.assertIn('/usr/lib/systemd/system', seen)


if __name__ == '__main__':
    unittest.main()
