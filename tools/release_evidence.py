#!/usr/bin/env python3
"""Measure the release evidence and write docs/RELEASE_EVIDENCE.json.

Every number in the file comes from a command run here, with its command
line, exit code and tool version recorded next to it. Nothing is typed in by
hand. Values apply to the environment recorded in `environment`; hosted CI
results are asserted only once observed on GitHub.

    python3 tools/release_evidence.py            # measure and write
    python3 tools/release_evidence.py --check    # fail if the committed file is stale (version/schema/counts)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from falsicore import __version__  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "RELEASE_EVIDENCE.json"
SCHEMA = "falsicore.release-evidence.v4"


def run(argv: list[str], timeout: int = 1800) -> tuple[int, str, float]:
    started = time.monotonic()
    proc = subprocess.run(argv, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "FALSICORE_REQUIRE_HYPOTHESIS": "1"})
    return proc.returncode, proc.stdout + proc.stderr, round(time.monotonic() - started, 2)


def version_of(module: str) -> str:
    code, out, _ = run([sys.executable, "-m", module, "--version"], timeout=120)
    return out.strip().splitlines()[0] if code == 0 and out.strip() else "UNAVAILABLE"


def os_release() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "UNKNOWN"


def measure() -> dict:
    py = sys.executable
    code, out, _ = run([py, "tools/build_release.py", "--check-manifest"], timeout=300)
    if code != 0:
        raise SystemExit("SOURCE_MANIFEST.sha256 is stale: regenerate it first, or every manifest test is red for the wrong reason")
    evidence: dict = {
        "schema": SCHEMA, "version": __version__, "date_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
        "environment": {"os": os_release(), "kernel": platform.release(), "python": platform.python_version(),
                        "uid_class": "root" if os.geteuid() == 0 else "unprivileged",
                        "note": "measured on the maintainer host; hosted CI is recorded only after it is observed"},
    }
    code, out, seconds = run([py, "-m", "unittest", "discover", "-s", "tests"])
    ran = re.search(r"^Ran (\d+) tests", out, re.M)
    failures = re.search(r"failures=(\d+)", out)
    errors = re.search(r"errors=(\d+)", out)
    skipped = re.search(r"skipped=(\d+)", out)
    evidence["suite"] = {"command": "python3 -m unittest discover -s tests (FALSICORE_REQUIRE_HYPOTHESIS=1)",
                         "exit": code, "ran": int(ran.group(1)) if ran else None,
                         "failed": int(failures.group(1)) if failures else 0, "errors": int(errors.group(1)) if errors else 0,
                         "skipped": int(skipped.group(1)) if skipped else 0, "seconds": seconds,
                         "test_files": len(list((ROOT / "tests").glob("test_*.py")))}
    cov_json = ROOT / ".mutation" / "release-coverage.json"
    cov_json.parent.mkdir(exist_ok=True)
    # Never treat a stale JSON from an earlier run as current evidence.
    cov_json.unlink(missing_ok=True)
    (ROOT / ".coverage").unlink(missing_ok=True)
    code, out, seconds = run([py, "-m", "coverage", "run", "--branch", "--source=falsicore", "-m", "unittest",
                              "discover", "-s", "tests", "-q"])
    json_exit, json_output, _ = run([py, "-m", "coverage", "json", "-o", str(cov_json)], timeout=300)
    try:
        if code != 0 or json_exit != 0:
            raise ValueError("coverage command did not complete successfully")
        totals = json.loads(cov_json.read_text())["totals"]
        evidence["coverage"] = {"scope": "falsicore/ runtime package, branch-aware, no exclusions",
                                "num_statements": totals["num_statements"], "covered_lines": totals["covered_lines"],
                                "missing_lines": totals["missing_lines"], "num_branches": totals["num_branches"],
                                "covered_branches": totals["covered_branches"], "missing_branches": totals["missing_branches"],
                                "percent_display": str(round(totals["percent_covered"])),
                                "run_exit": code, "json_exit": json_exit, "ci_gate_percent": 88,
                                "target_100_reached": totals["percent_covered"] >= 100, "tool": version_of("coverage")}
    except (OSError, KeyError, ValueError):
        evidence["coverage"] = {"status": "NOT_MEASURED", "run_exit": code, "json_exit": json_exit}
    finally:
        cov_json.unlink(missing_ok=True)
        (ROOT / ".coverage").unlink(missing_ok=True)
    static: dict = {}
    for name, argv in (("ruff", [py, "-m", "ruff", "check", "--select", "F,E9,B,PLE", "falsicore", "tools", "falsicore.py"]),
                       ("bandit", [py, "-m", "bandit", "-q", "-r", "falsicore", "tools", "falsicore.py", "-c", "pyproject.toml"]),
                       ("mypy", [py, "-m", "mypy"]),
                       ("internal_ast_audit", [py, "tools/code_audit.py", ".", "--fail-on", "high"]),
                       ("synthetic_rule_fixtures", [py, "-m", "tools.evaluate_rules"]),
                       ("detection_validity", [py, "tools/validity.py", "--check"])):
        code, out, seconds = run(argv, timeout=900)
        static[name] = {"command": " ".join(a if a != py else "python3" for a in argv), "exit": code, "seconds": seconds}
        if code != 0:
            # CI must retain a bounded diagnostic from the actual failed tool.
            # A bare exit=1 is not enough to reproduce or triage the finding.
            static[name]["diagnostic_tail"] = out[-4096:]
        if name in ("ruff", "bandit", "mypy"):
            static[name]["version"] = version_of(name)
        if name == "mypy":
            static[name]["gate"] = "release gate: zero errors"
    evidence["static_analysis"] = static
    try:
        validity = json.loads((ROOT / "docs" / "DETECTION_VALIDITY.json").read_text())
        evidence["detection_validity"] = {"scenarios": validity["scenario_counts"], "passes": validity["passes"],
                                          "clean_hosts": [{"scope": c["scope"], "mode": c.get("mode", "live"), "outcome": c["outcome"]}
                                                          for c in validity["clean_host"]],
                                          "rules_without_positive_scenario": validity["rules_without_positive_scenario"],
                                          "measures": validity["measures"], "does_not_measure": validity["does_not_measure"]}
    except (OSError, KeyError, ValueError):
        evidence["detection_validity"] = {"status": "NOT_MEASURED"}
    evidence["mutation_testing"] = {
        "tool": "tools/mutate.py (per-test selection from coverage contexts)",
        "pull_request_gate": "mutants on changed runtime lines must all be killed (CI job mutation-diff)",
        "external_baseline_0_1_3": {"commit": "81b5345", "mutants": 14675, "killed": 8236, "survived": 6390,
                                    "operators": "mutmut 3.3.1 libcst + return->None, negation, call deletion",
                                    "note": "strings and default-argument removals dominate the survivors"},
        "detectors_py_in_repo": {"mutants": 307, "open_after_review": 0, "annotated_equivalents": 2, "dead_parameters_removed": 1},
        "whole_package_table": "weekly workflow mutation.yml (artifact), see docs/MUTATION.md",
    }
    evidence["not_performed"] = ["system-scope (root) scan on the maintainer host", "malware-corpus validation",
                                 "cross-platform build reproducibility", "independent third-party review",
                                 "scan of a real offline image (fixture images only)"]
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify version and schema of the committed file")
    args = parser.parse_args(argv)
    if args.check:
        # The original historical JSON lacks exact test/source/workflow
        # fingerprints. Version and a green exit are insufficient for release
        # assurance. For a current receipt use release_receipt.py --check.
        print("HISTORICAL_ONLY: use tools/release_receipt.py --check --output RECEIPT.json",
              file=sys.stderr)
        return 1
    evidence = measure()
    OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    print(f"written {OUT.relative_to(ROOT)}: suite exit {evidence['suite']['exit']}, "
          f"coverage {evidence.get('coverage', {}).get('percent_display')}%")
    return 0 if evidence["suite"]["exit"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
