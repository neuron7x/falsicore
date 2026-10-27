#!/usr/bin/env python3
"""Fixed, labeled rule-recognition fixtures, NOT an empirical malware corpus."""
from __future__ import annotations
import ast
import json
import sys
from tools.code_audit import inspect_ast

FIXTURES = (
    ("dynamic_exec", "x=eval('1+1')", "FC-AST-001"),
    ("shell_spawn", "import subprocess\nsubprocess.run('echo x',shell=True)", "FC-AST-002"),
    ("command_interpreter", "from os import system as dispatch\ndispatch('echo x')", "FC-AST-003"),
    ("untrusted_pickle", "import pickle as pk\nx=pk.loads(b'payload')", "FC-AST-004"),
    ("tempfile_race", "import tempfile\np=tempfile.mktemp()", "FC-AST-005"),
    ("tls_disable", "import requests as rq\nrq.get('https://site.example',verify=False)", "FC-AST-006"),
    ("no_process_timeout", "import subprocess\nsubprocess.run(['echo','hello'])", "FC-AST-007"),
    ("silent_broad_error", "try:\n x=1\nexcept Exception:\n pass", "FC-AST-008"),
    ("world_writable", "from pathlib import Path\nPath('result').chmod(0o777)", "FC-AST-009"),
    ("json_deserialize", "import json\nx=json.loads('{}')", None),
    ("bounded_process", "import subprocess\nsubprocess.run(['echo', 'hi'],timeout=5,shell=False)", None),
    ("safe_temp_dir", "import tempfile\nwith tempfile.TemporaryDirectory() as td:\n pass", None),
    ("tls_default", "import requests\nrequests.get('https://site.example',timeout=5)", None),
    ("private_mode", "import os\nos.chmod('result',0o600)", None),
    ("narrow_cleanup", "try:\n f()\nexcept ProcessLookupError:\n pass", None),
    ("json_text", "text='os.system(\\\"malicious\\\")'", None),
    ("no_exec", "def execute():\n return 'hello'", None),
    ("ordinary_timeout", "import subprocess as sp\nsp.run(['date'],timeout=10)", None),
)


def evaluate() -> dict:
    tp = fp = tn = fn = 0
    mismatches = []
    for name, code, expected in FIXTURES:
        matches = {v["rule"] for v in inspect_ast(ast.parse(code), "fixture.py")}
        if expected is None:
            if matches:
                fp += 1
                mismatches.append({"fixture": name, "expected": [], "observed": sorted(matches)})
            else:
                tn += 1
        elif matches == {expected}:
            tp += 1
        else:
            fn += 1
            mismatches.append({"fixture": name, "expected": [expected], "observed": sorted(matches)})
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    return {"schema": "falsicore.rule-fixtures.v1", "dataset": "FIXED_SYNTHETIC_CODE_PATTERNS",
            "fixture_count": len(FIXTURES), "true_positive": tp, "true_negative": tn,
            "false_positive": fp, "false_negative": fn,
            "precision_on_fixtures": p, "recall_on_fixtures": r,
            "passed": not mismatches, "mismatches": mismatches,
            "caveat": "Rule-recognition only. NOT representative attacks, malware detection accuracy, or CVE exploitability."}


def main() -> int:
    result = evaluate()
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
