# FALSICORE — Codex / Astra Instructions

**Task:** autonomously complete evidence-first engineering for [PR #19](https://github.com/neuron7x/falsicore/pull/19) on branch `assurance/verification-foundation-2026-11`, targeting protected `main`. The owner delegates implementation, CI remediation, validation and integration preparation, but **owner alone decides and executes merge**. The latest PR-specific instruction supersedes earlier conditional-merge delegation. **Never merge, enable auto-merge, bypass protections or push to `main`.** The PR stays `MERGE HOLD` until the owner explicitly decides otherwise.

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

## Merge authority: reserved exclusively to the owner
**Never merge or enable auto-merge. Owner alone decides and executes merge, including after every gate passes.** Codex may prepare an independently verifiable exact-HEAD pre-merge report and recommend `READY_FOR_OWNER_REVIEW` only if all FC-01–39 requirements and applicable G0–G8 evidence are satisfied, no unresolved critical/high risks or non-equivalent security-critical mutations remain, all checks finish green at the latest HEAD, and authenticated signer, branch-policy, artifact and environment proofs exist. Otherwise retain `MERGE HOLD` and enumerate exact blockers. Pre-merge evidence does not prove release-only facts that require protected `main`; these remain explicitly `PENDING_POST_MERGE` and are not `PASS`.

**Never push to `main`, merge another PR, bypass protection (`--admin`), disable checks, rewrite historical tags or manufacture field evidence.** Even after owner authorization in a future run, do not infer rights to perform a merge from this standing contract. Only the owner can make that decision.
