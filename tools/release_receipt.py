#!/usr/bin/env python3
"""Fail-closed, fingerprint-bound release evidence; separate from historical snapshots.

Usage:
  python tools/release_receipt.py --output /tmp/receipt.json
  python tools/release_receipt.py --check --output /tmp/receipt.json

A local SHA-256 content commitment is not a digital signature or remote attestation.
This gate verifies measured values on the current checkout, not malware efficacy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from falsicore import __version__
from tools import build_release, release_evidence

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "falsicore.release-receipt.v1"
REQUIRED_STATIC = ("ruff", "bandit", "mypy", "internal_ast_audit",
                   "synthetic_rule_fixtures", "detection_validity")


def input_fingerprint() -> str:
    """Hash exact source, tests and CI workflow bytes, excluding the receipt.

    Excluding only the historical evidence JSON avoids a recursive hash
    dependency when that historical snapshot is regenerated separately.
    """
    digest = hashlib.sha256()
    paths = [*build_release.source_files(), *build_release.automation_files()]
    for path in sorted(paths, key=lambda p: p.relative_to(ROOT).as_posix()):
        name = path.relative_to(ROOT).as_posix()
        if name == "docs/RELEASE_EVIDENCE.json":
            continue
        content = build_release._read_safe_source(path)
        digest.update(name.encode("utf-8") + b"\\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def manifest_fingerprint() -> str:
    return hashlib.sha256((ROOT / "SOURCE_MANIFEST.sha256").read_bytes()).hexdigest()


def repository_head() -> str | None:
    """Return the actual checkout HEAD; an environment variable is not proof."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
            check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    head = proc.stdout.strip()
    return head if re.fullmatch(r"[0-9a-f]{40}", head) else None


def defects(receipt: dict) -> list[str]:
    problems: list[str] = []
    if receipt.get("schema") != SCHEMA or receipt.get("runtime_version") != __version__:
        problems.append("schema/runtime-version")
    if receipt.get("input_sha256") != input_fingerprint():
        problems.append("source-test-workflow-fingerprint")
    if receipt.get("manifest_sha256") != manifest_fingerprint():
        problems.append("source-manifest-fingerprint")
    observed_head = repository_head()
    if observed_head is None or receipt.get("git_head_sha") != observed_head:
        problems.append("exact-git-head-not-verified")
    if receipt.get("head_consistent") is not True:
        problems.append("git-head-changed-during-measurement")
    if receipt.get("sources_consistent") is not True:
        problems.append("source-changed-during-measurement")
    evidence = receipt.get("measurements")
    if not isinstance(evidence, dict):
        return problems + ["no-measurements"]
    suite = evidence.get("suite", {})
    if not isinstance(suite, dict) or (
        suite.get("exit") != 0 or not isinstance(suite.get("ran"), int)
        or suite["ran"] <= 0 or suite.get("errors") != 0 or suite.get("failed") != 0
        or suite.get("test_files") != len(list((ROOT / "tests").glob("test_*.py")))
    ):
        problems.append("suite")
    coverage = evidence.get("coverage", {})
    if not isinstance(coverage, dict):
        problems.append("coverage")
    else:
        values = [coverage.get(k) for k in ("num_statements", "covered_lines",
                                            "missing_lines", "num_branches",
                                            "covered_branches", "missing_branches")]
        if (not all(type(v) is int and v >= 0 for v in values)
                or type(coverage.get("run_exit")) is not int
                or coverage["run_exit"] != 0
                or type(coverage.get("json_exit")) is not int
                or coverage["json_exit"] != 0
                or values[0] <= 0 or values[3] <= 0
                or values[1] + values[2] != values[0]
                or values[4] + values[5] != values[3]
                or 100.0 * (values[1] + values[4]) / (values[0] + values[3]) < 88):
            problems.append("coverage-unmeasured-or-below-88")
    static = evidence.get("static_analysis", {})
    if not isinstance(static, dict):
        static = {}
    for key in REQUIRED_STATIC:
        row = static.get(key)
        if not isinstance(row, dict) or row.get("exit") != 0:
            problems.append("static:" + key)
    validity = evidence.get("detection_validity", {})
    if (not isinstance(validity, dict) or validity.get("passes") is not True
            or validity.get("rules_without_positive_scenario") != []):
        problems.append("synthetic-validity")
    return problems


def capture() -> dict:
    head = repository_head()
    first = input_fingerprint()
    manifest = manifest_fingerprint()
    measurements = release_evidence.measure()
    return {"schema": SCHEMA, "runtime_version": __version__,
            "git_head_sha": head,
            "head_consistent": head is not None and head == repository_head(),
            "input_sha256": first, "manifest_sha256": manifest,
            "sources_consistent": first == input_fingerprint() and
            manifest == manifest_fingerprint(),
            "measurements": measurements,
            "limitation": "No external malware corpus, privileged host, independent review, or signed attestation is established."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("receipt must be outside the repository to avoid self-referential inputs")
    if args.check:
        try:
            document = json.loads(args.output.read_text())
            failures = defects(document)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print("RECEIPT_NOT_VERIFIED: " + type(exc).__name__, file=sys.stderr)
            return 1
    else:
        document = capture()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        failures = defects(document)
    if failures:
        print("RECEIPT_NOT_VERIFIED: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("RECEIPT_VERIFIED: exact input SHA-256, suite, coverage, static checks and synthetic validity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
