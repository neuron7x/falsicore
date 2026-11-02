#!/usr/bin/env python3
"""Check that the work registry faithfully carries the frozen audit's 39 findings.

This checks planning data only. It does not run tests, verify claims, or grant
release assurance. Run from any directory with Python 3.10+.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'docs/verification/source/FINDINGS.json'
TASKS = ROOT / 'docs/verification/tasks.json'
IDS = {f'FC-{i:02d}' for i in range(1, 40)}
SOURCE_SHA256 = 'cbc6c13f491f6cc8a927faa5abd9ddf55fd7a04ccecc26ef48389aa67890d141'


def source_digest_ok(raw: bytes) -> bool:
    return hashlib.sha256(raw).hexdigest() == SOURCE_SHA256


def check(source: object, tasks: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(source, dict) or not isinstance(source.get('findings'), list):
        return ['source findings must be a list']
    if not isinstance(tasks, list):
        return ['tasks must be a list']

    def index(items: list, label: str) -> dict:
        indexed = {}
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                errors.append(f'{label}: invalid entry/id')
                continue
            key = item['id']
            if key in indexed:
                errors.append(f'{label}: duplicate {key}')
            indexed[key] = item
        missing, extra = IDS - indexed.keys(), indexed.keys() - IDS
        if missing or extra:
            errors.append(f'{label}: missing={sorted(missing)} extra={sorted(extra)}')
        return indexed

    original = index(source['findings'], 'source')
    registry = index(tasks, 'registry')
    for key in sorted(IDS & original.keys() & registry.keys()):
        src, task = original[key], registry[key]
        for field in ('falsifier', 'evidence_url', 'priority', 'evidence_class', 'area', 'title', 'source_path'):
            if not isinstance(src.get(field), str) or not src[field].strip():
                errors.append(f'{key}: source missing {field}')
            elif task.get(field) != src[field]:
                errors.append(f'{key}: {field} differs from source')
        for field in ('acceptance', 'state'):
            if not isinstance(task.get(field), str) or not task[field].strip():
                errors.append(f'{key}: missing {field}')
        state = task.get('state')
        if state not in {'NOT_RUN', 'IN_PROGRESS', 'BLOCKED', 'INCONCLUSIVE', 'FAIL', 'PASS'}:
            errors.append(f'{key}: invalid state')
        if state == 'PASS':
            if not isinstance(task.get('evidence'), str) or not task['evidence'].strip():
                errors.append(f'{key}: PASS requires an evidence reference')
            if not isinstance(task.get('candidate_sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', task['candidate_sha']):
                errors.append(f'{key}: PASS requires a full candidate commit SHA')
        deps = task.get('dependencies')
        if not isinstance(deps, list) or any(not isinstance(d, str) or d not in IDS or d == key for d in deps):
            errors.append(f'{key}: invalid dependencies')
    return errors


def main() -> int:
    try:
        source_bytes = SOURCE.read_bytes()
        if not source_digest_ok(source_bytes):
            print('FAIL: source audit digest mismatch', file=sys.stderr)
            return 1
        source = json.loads(source_bytes)
        tasks = json.loads(TASKS.read_text(encoding='utf-8'))
        errors = check(source, tasks)
    except (OSError, ValueError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f'FAIL: {error}', file=sys.stderr)
        return 1
    print('PASS: 39 registry entries match audit source; no execution claims checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
