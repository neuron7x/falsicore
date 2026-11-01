#!/usr/bin/env python3
"""Local release gate: the same checks as CI, run before every push.

Every step records its exact command and exit code; the gate fails closed
(a missing analysis tool is a failure, not a skip, unless --allow-missing-tools).
Nothing here edits the tree. Output is a machine-readable JSON summary on
stdout plus one line per step on stderr.

    python3 tools/gate.py            # full gate (needs the dev tools from pyproject)
    python3 tools/gate.py --quick    # tests + manifest + static audit only
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE_GATE = 88  # must equal the CI gate in .github/workflows/verify.yml


def _module_available(name: str) -> bool:
    probe = subprocess.run([sys.executable, "-c", f"import {name}"], capture_output=True, timeout=60)
    return probe.returncode == 0


def _binary(name: str) -> str:
    """Absolute path of a required host tool; the gate fails closed without it."""
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"required tool missing: {name}")
    return found


class Gate:
    def __init__(self, allow_missing: bool) -> None:
        self.steps: list[dict] = []
        self.allow_missing = allow_missing
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

    def run(self, name: str, argv: list[str], timeout: int = 900, cwd: Path | None = None,
            env: dict[str, str] | None = None) -> bool:
        started = time.monotonic()
        try:
            proc = subprocess.run(argv, cwd=str(cwd or ROOT), env=env or self.env, capture_output=True,
                                  text=True, timeout=timeout)
            code: int | None = proc.returncode
            tail = (proc.stdout + proc.stderr)[-4000:]
        except subprocess.TimeoutExpired:
            code, tail = None, "TIMEOUT"
        passed = code == 0
        self.steps.append({"step": name, "argv": argv, "exit": code, "passed": passed,
                           "seconds": round(time.monotonic() - started, 2), "tail": tail})
        print(f"{'PASS' if passed else 'FAIL'} {name} (exit={code})", file=sys.stderr, flush=True)
        if not passed:
            print(tail, file=sys.stderr, flush=True)
        return passed

    def tool(self, name: str, module: str, argv: list[str], timeout: int = 900) -> bool:
        if not _module_available(module):
            status = "MISSING_TOOL_ALLOWED" if self.allow_missing else "MISSING_TOOL"
            self.steps.append({"step": name, "argv": argv, "exit": None, "passed": self.allow_missing,
                               "seconds": 0.0, "tail": status})
            print(f"{'SKIP' if self.allow_missing else 'FAIL'} {name} ({status}: {module})", file=sys.stderr, flush=True)
            return self.allow_missing
        return self.run(name, argv, timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quick", action="store_true", help="skip static analysers, coverage and double builds")
    parser.add_argument("--allow-missing-tools", action="store_true",
                        help="treat an absent dev tool as SKIP instead of FAIL (never in CI)")
    args = parser.parse_args(argv)
    py = sys.executable
    sha256sum, cmp = _binary("sha256sum"), _binary("cmp")
    git = shutil.which("git")
    gate = Gate(args.allow_missing_tools)
    os.umask(0o022)  # CI-like umask; permission tests assume it
    before_status = ""
    if git:
        probe = subprocess.run([git, "status", "--porcelain"], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        before_status = probe.stdout if probe.returncode == 0 else ""

    gate.run("manifest", [sha256sum, "-c", "--quiet", "SOURCE_MANIFEST.sha256"])
    gate.run("manifest-current", [py, "tools/build_release.py", "--check-manifest"])
    gate.run("syntax", [py, "-m", "compileall", "-q", "falsicore", "falsicore.py", "tools"])
    test_env = dict(gate.env)
    if _module_available("hypothesis"):
        test_env["FALSICORE_REQUIRE_HYPOTHESIS"] = "1"
    gate.run("unittest", [py, "-m", "unittest", "discover", "-s", "tests", "-q"], env=test_env)
    gate.run("source-audit", [py, "tools/code_audit.py", ".", "--fail-on", "high"])
    gate.run("rule-fixtures", [py, "-m", "tools.evaluate_rules"])
    gate.run("detection-validity", [py, "tools/validity.py", "--check"])
    gate.run("release-evidence-current", [py, "tools/release_evidence.py", "--check"])
    if not args.quick:
        gate.tool("ruff", "ruff", [py, "-m", "ruff", "check", "--select", "F,E9,B,PLE", "falsicore", "tools", "falsicore.py"])
        gate.tool("bandit", "bandit", [py, "-m", "bandit", "-q", "-r", "falsicore", "tools", "falsicore.py", "-c", "pyproject.toml"])
        gate.tool("mypy", "mypy", [py, "-m", "mypy"])
        if gate.tool("coverage-run", "coverage",
                     [py, "-m", "coverage", "run", "--branch", "--source=falsicore", "-m", "unittest", "discover", "-s", "tests", "-q"]):
            gate.run("coverage-gate", [py, "-m", "coverage", "report", f"--fail-under={COVERAGE_GATE}"])
        with tempfile.TemporaryDirectory(prefix="falsicore-gate-") as tmp:
            out = Path(tmp)
            ok = gate.run("build-pyz-a", [py, "tools/build_app.py", str(out / "a.pyz")])
            ok = gate.run("build-pyz-b", [py, "tools/build_app.py", str(out / "b.pyz")]) and ok
            if ok:
                gate.run("pyz-identical", [cmp, str(out / "a.pyz"), str(out / "b.pyz")])
                gate.run("pyz-verify-app", [py, "-I", str(out / "a.pyz"), "verify-app"])
            ok = gate.run("build-full-a", [py, "tools/build_full.py", str(out / "fa")])
            ok = gate.run("build-full-b", [py, "tools/build_full.py", str(out / "fb")]) and ok
            if ok:
                za, zb = sorted(out.joinpath("fa").glob("*.zip")), sorted(out.joinpath("fb").glob("*.zip"))
                if len(za) == 1 and len(zb) == 1:
                    gate.run("full-identical", [cmp, str(za[0]), str(zb[0])])
    if git:
        # The gate itself must not edit tracked files: compare the tree before and after.
        after = subprocess.run([git, "status", "--porcelain"], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        unchanged = after.returncode == 0 and after.stdout == before_status
        gate.steps.append({"step": "tree-unchanged-by-gate", "argv": ["git", "status", "--porcelain"],
                           "exit": after.returncode, "passed": unchanged, "seconds": 0.0,
                           "tail": "" if unchanged else after.stdout[-4000:]})
        print(f"{'PASS' if unchanged else 'FAIL'} tree-unchanged-by-gate", file=sys.stderr, flush=True)
    passed = all(s["passed"] for s in gate.steps)
    print(json.dumps({"schema": "falsicore.gate.v1", "passed": passed, "coverage_gate_percent": COVERAGE_GATE,
                      "python": sys.version.split()[0], "steps": gate.steps}, indent=2, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
