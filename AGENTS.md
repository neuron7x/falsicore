# FALSICORE — Codex / Astra Instructions

**Task:** autonomously close [PR #19](https://github.com/neuron7x/falsicore/pull/19) on branch `assurance/verification-foundation-2026-11` and, **only after a verified preflight**, merge it into protected `main`. The owner explicitly delegated implementation, CI remediation, validation, integration and conditional merge to the executing local Codex. Earlier owner-only merge restrictions are superseded **only for this agent and only after the gate**. The PR is currently `MERGE HOLD`: these instructions do not themselves authorize an immediate merge.

**Mission:** produce a defensible, fast, reliable, passive/read-only, offline-first Linux endpoint and forensic-image intrusion triage **instrument**, not a commercial product. No marketing, invented certification or unrelated features.

## Read the right evidence
For PR #19 execution, start with [`docs/CODEX_EXECUTION_CONTRACT.md`](docs/CODEX_EXECUTION_CONTRACT.md), which contains the dependency-ordered 39-FC program, falsification methodology, G0–G8 gates, release/merge protocol, benchmarks and primary external references. For a narrow change, read only its relevant sections, source and tests; avoid repeatedly loading unrelated documents.

- Frozen audit: `docs/verification/source/FALSICORE_VERIFICATION_ACT.md`, `FINDINGS.json`, `AUDIT_CHECKSUMS.txt`. Audited source was `41745142378ccab363974db9f3cd568188706524`; do not rewrite the audit to claim success.
- **Canonical 39-item registry:** `docs/verification/tasks.json`. Preserve its falsifiers, dependencies, evidence URLs and explicit `PASS/FAIL/BLOCKED` boundaries.
- Gate SSOT: `docs/VERIFICATION_PROGRAM.md` (G0–G8). Safety: `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/OPERATIONS.md`, `docs/ASSURANCE.md`, `docs/MUTATION.md`.
- Implementation truth: actual `falsicore/`, `tools/`, `tests/`, `.github/workflows/`, `pyproject.toml`, `SOURCE_MANIFEST.sha256`, the latest PR HEAD and CI logs.

## Non-negotiable rules
1. **Fail closed.** Incomplete observations, unknown syntax, hidden namespaces, truncated output, unreadable package metadata, missing proof or failed subcommand are not proof of safety or absence.
2. **Exact provenance.** Evaluate trust at the executable/code operand, source file, scope, signed artifact, SHA and run identity; neither a basename nor a checksum authenticates the producer.
3. **No target mutation.** FALSICORE scanning remains passive, offline, read-only, without network probes or privilege escalation. Privileged validation is confined to expressly authorized disposable environments. Never publish sensitive incident logs, host paths, identities, private indices or malware samples.
4. **Falsify every repair.** Run a red negative control on a deliberately faulty variant, then the same correct/benign/limit cases green. Do not "fix" CI by skips, metric denominator tricks, severity demotion, fake data or blanket mutation waivers.
5. **Current-SHA evidence only.** Re-measure all required tools, full Python 3.10–3.14 matrix, coverage/static/code security, mutation (changed-line **and** whole-package), source-bound receipt, packaged self-test and independent environmental/field validity. Old green runs are historical.
6. **Atomic source integrity.** Use `python tools/build_release.py --write-manifest` after changing source/tests/allowlisted docs, verify `--check-manifest`, commit the manifest with the implementation. Coordinate parallel agents with fresh HEAD and compare-and-swap / fast-forward; **never force-push**.
7. **Performance by measurements.** Baseline representative quick/standard/deep workloads and record p50/p95, CPU, peak RSS, I/O, error/coverage completeness and benign false alarms. Never sacrifice correctness for speed.
8. **Truthful reporting.** Use `FACT/INFERENCE/BLOCKED`, exact SHA, failing and passing commands, CI/artifact URLs, per-FC status and residual risk. No claim of "zero vulnerabilities" or academic/industry certification.

## Execute, do not only plan
Refresh current PR head and recent failed job logs. First fix the **current** RED test or evidence gate, then dependency-order code/trust/cross-view/offline/mutation/release and G7–G8 validation. Close a task only with its exact acceptance proof, faulty negative control and independently observable current-SHA CI. Repeat until the gates are satisfied or a genuinely external prerequisite blocks you.

Baseline commands: `python assurance/check_registry.py`; `python -m unittest discover -s assurance -q`; `python -m unittest discover -s tests -q` with Hypothesis required; `python tools/build_release.py --check-manifest`; `python tools/validity.py --check`; `python tools/mutate.py --coverage` then strict `--diff origin/main` and independently `--all`; `python tools/release_receipt.py --output /tmp/falsicore-receipt.json` and `--check` for the same path. Follow the complete exact-head and external gate matrix in the execution contract.

## Merge authority: objective preconditions only
Normal merge of **this PR only** is delegated once **all pre-merge-verifiable FC and G0–G8 criteria** have genuine current evidence; no known critical/high security issue, non-equivalent security-critical mutation or incomplete mandatory check remains; external required evidence is real; protected-branch checks and signer trust are independently verified; the final source, tests and candidate artifacts are reproducible and attested. The release-dependent facts that *logically require post-merge main* must have a validated signed-candidate preflight, be explicitly `PENDING_POST_MERGE`, and be completed/verified **after** merge before any release-ready claim. These must never be marked `PASS` prematurely. If the upstream contract disallows that two-stage sequence, keep merge blocked; document the circular dependency.

Never bypass protection (`--admin`), disable checks, modify `main` except through the authorized normal merge, rewrite historical tags, or manufacture field/external evidence. If a prerequisite is unavailable, retain `MERGE HOLD` and specify the exact missing data/access. Once authorized preflight genuinely passes, merge PR #19, verify `main` and complete the post-merge signing/SBOM/attestation verification.
