"""Static contract checks: no sockets, eval, shell=True, curl-to-shell, destructive subprocesses."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]

class StaticContractTests(unittest.TestCase):
    def modules(self):
        return list((ROOT / "falsicore").glob("*.py"))

    def test_no_net_libraries_imported(self):
        blocked = {"socket", "requests", "urllib", "http.client", "ftplib", "paramiko", "boto3"}
        for file in self.modules():
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse({alias.name for alias in node.names} & blocked, file)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, blocked, file)

    def test_no_dynamic_code_execution(self):
        for file in self.modules():
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"eval", "exec", "compile", "__import__"}, file)

    def test_no_shell_true(self):
        for file in self.modules():
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    self.assertIsInstance(node.value, ast.Constant, file)
                    self.assertFalse(node.value.value, file)

    def test_no_direct_system_shell(self):
        for file in self.modules():
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        self.assertNotIn((node.func.value.id, node.func.attr), {
                            ("os", "system"), ("os", "popen"), ("subprocess", "run"),
                            ("subprocess", "call"), ("subprocess", "check_output")}, file)

    def test_runner_disables_pycache(self):
        self.assertIn("sys.dont_write_bytecode = True", (ROOT / "falsicore.py").read_text())

    def test_allowlist_has_no_download_shell(self):
        from falsicore.safety import COMMAND_ALLOWLIST
        self.assertFalse({"bash", "sh", "python", "python3", "curl", "wget", "pip", "apt", "rm", "chmod", "chown"} & COMMAND_ALLOWLIST)

    def test_no_web_upload_keywords_in_code(self):
        files = "\n".join(p.read_text() for p in self.modules())
        for token in ("requests.post(", "urllib.request.urlopen(", "socket.socket("):
            self.assertNotIn(token, files)
