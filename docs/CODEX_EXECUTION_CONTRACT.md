# FALSICORE PR #19 — Autonomous Codex / Astra Engineering Closure Contract

**Contract:** `falsicore.codex-assurance-execution.v1`  
**Date drafted:** 2026-11-01  
**Target:** `neuron7x/falsicore`, PR [#19](https://github.com/neuron7x/falsicore/pull/19), head branch `assurance/verification-foundation-2026-11`, base branch `main`  
**Status:** EXECUTION MANDATE; **NOT** a passing assurance report  
**Original audited SHA:** `41745142378ccab363974db9f3cd568188706524`  
**Starting reference (historical; re-read GitHub when running):** `e78adaa368b4d5c3f73cadff83109762b6f4c378`

## 0. User mandate, scope and success predicate

The owner delegates full end-to-end engineering, local testing, review, fixes, source-control commits, CI evidence, field-validation coordination, release readiness, and **conditional merge of PR #19** to the incoming local Codex agent. The older instruction "owner alone may merge" is superseded for that agent by this subsequent explicit delegation. The **MERGE HOLD** remains in force until the objective preflight below actually passes. Never merge merely because the agent was delegated authority. Never bypass protection or invent authority unavailable to GitHub credentials.

FALSICORE is a **research/operations instrument**, not a SaaS, storefront or product to monetize. The intended capability is an offline-first, read-only Linux endpoint/forensic-image intrusion triage system with falsifiable detection claims, bounded resource usage, safe evidence handling and reproducible releases. Avoid unrelated features, frameworks, redesigns or marketing. Optimize correctness, coverage, performance and observability of existing contracts before expansion.

"Zero debt" means **zero known unresolved release-blocking implementation defects, critical/high-severity security findings, unqualified security-critical mutants, incomplete required checks and false evidence claims within the declared scope**. It does **not** mean omniscience or a proof that no latent vulnerability exists. Declare residual unknowns. "US industry/academic quality" is an engineering *target*, measurable by the same controls, independent falsification and reproducibility, **not** a certification or reputation claim.

## 1. Canonical material and exact authority order

1. User's latest task-specific instructions, then root [`AGENTS.md`](../AGENTS.md).
2. **Frozen original audit**: [`docs/verification/source/FALSICORE_VERIFICATION_ACT.md`](verification/source/FALSICORE_VERIFICATION_ACT.md), [`FINDINGS.json`](verification/source/FINDINGS.json), [`AUDIT_CHECKSUMS.txt`](verification/source/AUDIT_CHECKSUMS.txt). Verify original SHA-256 and never alter its semantic evidence, source links or 39 IDs to manufacture closure.
3. **Single source of truth for work units**: [`docs/verification/tasks.json`](verification/tasks.json). The per-FC `falsifier`, `acceptance`, `priority`, `dependencies`, and `evidence_class` are controlling; this document is an execution index, not a replacement.
4. [`docs/VERIFICATION_PROGRAM.md`](VERIFICATION_PROGRAM.md) defines the G0–G8 contracts and distinguishes `SC` (source-confirmed), `RR` (review-reproduced) and `EG` (missing evidence). Absence of evidence is neither proof of a defect nor proof of correctness.
5. Actual runtime and workflows: `falsicore/`, `falsicore.py`, `tools/`, `tests/`, `assurance/`, `.github/workflows/`, `pyproject.toml`, `SOURCE_MANIFEST.sha256`. Read the precise code you change, not old PR summaries.
6. [`SECURITY.md`](../SECURITY.md), [`docs/THREAT_MODEL.md`](THREAT_MODEL.md), [`docs/OPERATIONS.md`](OPERATIONS.md), [`docs/ASSURANCE.md`](ASSURANCE.md), [`docs/MUTATION.md`](MUTATION.md) and [`docs/GITHUB_RELEASE.md`](GITHUB_RELEASE.md) define safety/claims and existing operational semantics.
7. External primary references in §12 describe **requirements and methods**, not claims of NIST, OpenSSF, SLSA, GitHub or academic certification.

Trust order for claims: executable negative control + passing positive regression + source hash + current-head CI receipt + independent reproduction > current code inspected > previous CI or PR comments > agent assertions. Always distinguish `FACT`, `INFERENCE`, `HYPOTHESIS`, `UNMEASURED`.

## 2. First-principles invariants — prove, do not recite

- **I1 / Observation completeness:** an absent indicator is meaningful only inside a fully observed, declared scope. Error, EOF, truncation, permission denial, unknown policy, missing namespace, or failed recheck produce explicit incomplete coverage. No `COMPLETED` with an incompleteness reason; no `PARTIAL` without one. Confirmed findings survive unrelated collector failures.
- **I2 / Precise trust identity:** never convert a pathname basename, user-controlled stream, package digest or trusted binary into a trusted arbitrary evaluation. Bind identity and execution taint to the exact operand, file, calling context, privilege domain and source digest.
- **I3 / Parsers cannot silently accept unknowns:** nested parameter substitution, process substitution, backticks, heredoc, quoting, redirection and interpreter flags must be classified or explicitly reported unsupported. Bound recursion, input bytes, token count, execution time and memory. Do not turn unsupported shell into a guessed clean result.
- **I4 / Cross-view comparisons require compatibility:** compare PID/TID or socket facts across compatible namespaces, privilege, protocol family, bind address, port, observation epoch and collection completeness. Protect against PID reuse, race churn, hidepid and transient sockets. A single contrary sample is a candidate, not a rootkit verdict.
- **I5 / Offline means OFFLINE:** every read remains under the mounted image root, including intermediate links, TOCTOU/path swaps and journalctl directory arguments. Do not substitute live host information, execute scripts found in the image, mount untrusted media read-write or expose raw host content to public CI.
- **I6 / Measurements fail closed:** failing or omitted ancillary tools, stale coverage JSON, wrong git SHA, missing SBOM/signature, unexecuted mutants, timeout, inaccurate source manifest or false-green job wiring cannot produce a `PASS` receipt.
- **I7 / Performance and quality are empirical:** instrument latency distributions, throughput, CPU, peak RSS, file-descriptor count, bounded error recovery, resource budgets and metric variance; only compare like-for-like conditions with a pre-registered baseline.
- **I8 / Reproducible & attributable outputs:** same snapshot/inputs produce stable semantic findings and checksums. Do not conflate deterministic same-platform bytes with universal cross-platform byte identity or integrity with publisher authentication.
- **I9 / Security and privacy:** scanner is passive, unprivileged by default and read-only. No network probing from the scanner, no host mutation, no automatic privilege escalation. Never commit or publicly upload `private_index.json`, personal logs, usernames, source paths, credentials, cookies, field images or proprietary malware specimens.

## 3. Execution algorithm — mandatory for each wave

1. **Refresh HEAD:** `git fetch origin`; `git status --porcelain`; `git rev-parse HEAD`; `gh pr view 19 --json headRefOid,baseRefOid,state,mergeStateStatus`; inspect latest PR checks and each job's conclusion and timestamp. If parallel agents pushed, compare and rebase *without force*, or use expected-HEAD/CAS updates. Never overwrite another agent's commits.
2. **Choose the smallest linked defect group** from the dependency graph in §4. Prioritize actual RED CI, unsafe false-negative/false-positive mechanisms, evidence falsification and mutation survivors. A long written plan without an executable change is not a completed iteration.
3. **Extract its exact counterexample:** from the original audit, source, code, related GitHub review and current CI. State causal precondition, invariant violated, exploitation/false-proof boundary, benign rival explanation and minimal failure mechanism.
4. **Write falsifiers before the fix:** one positive scenario, one benign twin, one malformed/partial/timeout or boundary case. Run the faulty code or purposefully mutated variant in an isolated fixture and verify the *new test fails for the intended reason* (not fixture setup, accidental formatting or unrelated syntax).
5. **Implement a minimal sound repair:** prefer preserving semantics, fail-closed status and established APIs. If a safety finding is merely a weak assertion, eliminate the invalid assertion or measure the missing data; do not replace it with a hidden skip, blanket waiver or severity demotion.
6. **Verify:** targeted tests on each supported Python version where applicable; full suite; static type/lint/security; the 39-source registry checker; relevant CI; mutation survivor replay and resource caps. Preserve already green behaviors.
7. **Update evidence atomically:** source/test/allowlisted-doc change -> `python tools/build_release.py --write-manifest`, review exact `SOURCE_MANIFEST.sha256` diff, then `--check-manifest`. Commit code, tests and manifest together. Do not use `--allow-survivors` to obtain a green acceptance gate.
8. **Observe the exact pushed SHA:** wait for required checks to complete; only call a task `PASS` if its own falsifier, dependency gates, artifact and residual scope are independently demonstrable. Previous SHA receipts are historical, even if they were green.
9. **Report and continue:** compact batch log (e.g. 7–10 related FCs if technically coherent) with `FACT/INFERENCE/BLOCKED`, old/new SHA, failing-then-passing test, mutation counts, affected contracts, CI URLs, new residuals, decision for the next wave. Do not repeatedly re-run an unchanged failed task without changing the causal condition.

The agent may inspect or improve documentation and detection methods as needed, but must not mass-rewrite the frozen act or redefine acceptance to fabricate closure.

## 4. Priority, dependencies and work packages

| Wave | Gates / FC IDs | Execution objective and required hard evidence |
| --- | --- | --- |
| W0: bootstrap/current-RED | G0/G4/G5; FC-21/22/24/38 | Diagnose exact latest CI, regenerate fresh receipt, fix static-analysis/evidence/mutation failures; prove a failing ancillary tool forces red; establish repo and source/test SHA chain. |
| W1: executable syntax | G1; FC-01–09 | Reproduce shell taint and parser counterexamples, trust-boundary negatives, nested depth and input limits; close only with targeted falsifiers and preserved unrelated findings. |
| W2: Linux cross-view | G2; FC-10–13 | Exact socket address/family/protocol identity, hidepid scope, transient and truncated `ss`, procfs PID/TID consistency; no high-severity hidden-process claim from insufficient views. |
| W3: offline evidence | G3; FC-14–16, FC-30 | Root-constrained journal/image reads, dpkg/rpm/pacman/apk metadata completeness, omission budgets, false clean verdicts; real mounted read-only image confirmation. |
| W4: mutation credibility | G4; FC-17–19, FC-23, FC-29 | Mutation byte-span fidelity, multiline selection, no line-wide exemption, exact per-mutant equivalent proofs, strict per-PR and whole-package score, no `NOT_RUN`/`TIMEOUT` success. |
| W5: release/evidence mechanics | G0/G5; FC-20–22, FC-24–27, FC-38 | Runtime/package version parity, current test/coverage/security receipts, immutable source manifest, signed identity-bound tag, no self-hashing acceptance. |
| W6: governance & provenance | G6; FC-28, FC-37, FC-39 | Verified branch protection and required evidence check, signed source/build provenance, SBOM, actual verification commands and confidential disclosure configuration. |
| W7: field validity and environments | G7/G8; FC-31–36 | Representative held-out labeled corpora, false-alarm/precision/recall and latency statistics, disposable privileged host, provenance-verified offline image, cross-platform reproduction and genuinely independent challenge. |
| W8: operational optimization | cross-cutting | Frozen workload mix, correct metrics, p50/p95/p99 latency, peak RSS/CPU, resource ceilings, error rates, determinism, privacy and user runbooks; prove performance without losing detection or weakening safeguards. |
| W9: integration & release | G0–G8 | Exact-HEAD final acceptance, complete per-FC ledger, security-review closure, conditional merge under branch protection, then verify protected `main` and post-merge signed release artifacts. |

### Canonical FC index (generated from the original 39-task register)

Read each actual `falsifier` and `acceptance` in `tasks.json` before changing its state. This index is a **snapshot for navigation**, not a second registry.

| FC | Priority | Original finding title | Dependencies | Snapshot state |
| --- | --- | --- | --- | --- |
| FC-01 | P1 | Nested process-substitution loses context | — | IN_PROGRESS |
| FC-02 | P2 | Command substitution taint is aggregated across unrelated words | FC-08 | IN_PROGRESS |
| FC-03 | P2 | Here-string misclassified as network redirection | — | IN_PROGRESS |
| FC-04 | P2 | HOME-relative source path with double slash escapes base | FC-16 | IN_PROGRESS |
| FC-05 | P1 | Eval-site qualification uses aggregate counts | FC-06, FC-07, FC-08 | IN_PROGRESS |
| FC-06 | P2 | Relative executable name aliases packaged executable | — | IN_PROGRESS |
| FC-07 | P1 | Relay-program denylist is not sound | FC-06 | IN_PROGRESS |
| FC-08 | P1 | Nested command substitutions inside ${...} discarded | — | IN_PROGRESS |
| FC-09 | P2 | Unbounded recursive quote/parameter parser | — | IN_PROGRESS |
| FC-10 | P2 | hidepid mount visibility incorrectly treated as kernel hiding | — | IN_PROGRESS |
| FC-11 | P2 | Transient sockets create NETLINK_ONLY false alarm | FC-12, FC-13 | IN_PROGRESS |
| FC-12 | P2 | Partial ss output used for negative inference | — | IN_PROGRESS |
| FC-13 | P2 | Listener identity collapses address and network family | — | IN_PROGRESS |
| FC-14 | P2 | Offline RPM scope limit suppresses unrelated package failure | FC-15, FC-30 | IN_PROGRESS |
| FC-15 | P2 | Unreadable/over-budget dpkg metadata silently dropped | — | IN_PROGRESS |
| FC-16 | P2 | Offline journal parent symlink crosses root boundary | — | IN_PROGRESS |
| FC-17 | P2 | AST unparse causes false mutant kills | — | IN_PROGRESS |
| FC-18 | P2 | Continuation-line operator modifications omitted from diff mutations | FC-17 | IN_PROGRESS |
| FC-19 | P2 | Mutation budget expiry returns success with NOT_RUN | — | IN_PROGRESS |
| FC-20 | P2 | Package metadata version inconsistent with runtime | — | IN_PROGRESS |
| FC-21 | P2 | Evidence freshness accepts stale counts and coverage | FC-24, FC-38 | IN_PROGRESS |
| FC-22 | P2 | Evidence regeneration poisoned by self-referential test | FC-21 | IN_PROGRESS |
| FC-23 | P2 | Line-wide #no mutate hides behavior-changing mutants | FC-17 | IN_PROGRESS |
| FC-24 | P1 | Evidence generator success ignores failing ancillary measurements | — | IN_PROGRESS |
| FC-25 | P1 | Tag release job permits skipping property tests | FC-24 | IN_PROGRESS |
| FC-26 | P2 | Published tag trails main by six commits under same runtime version | FC-20 | BLOCKED |
| FC-27 | P2 | GitHub cannot verify SSH tag signature | — | BLOCKED |
| FC-28 | P1 | Default branch lacks branch protection/rulesets | — | BLOCKED |
| FC-29 | P2 | Whole-package scheduled job accepts survivors by design | FC-19, FC-23 | FAIL |
| FC-30 | P2 | Pacman mtree index silently discards incomplete database | — | IN_PROGRESS |
| FC-31 | P1-EG | No representative real-malware corpus validation | — | BLOCKED |
| FC-32 | P1-EG | Field false-alarm rate, precision and time to detection unknown | — | BLOCKED |
| FC-33 | P2-EG | No measured privileged system-scope host scan | FC-10, FC-11, FC-12, FC-13 | BLOCKED |
| FC-34 | P2-EG | No real mounted offline image evidence | FC-14, FC-15, FC-16, FC-30 | BLOCKED |
| FC-35 | P2-EG | Cross-platform reproducible build not established | FC-20, FC-37 | BLOCKED |
| FC-36 | P2-EG | Independent external implementation review not demonstrated | — | BLOCKED |
| FC-37 | P2-EG | Release assets lack demonstrated signed build attestation and SBOM | FC-27 | BLOCKED |
| FC-38 | P1 | Release evidence has no exact source/test fingerprint | FC-24 | IN_PROGRESS |
| FC-39 | P2-EG | Private vulnerability disclosure configuration not confirmed | — | BLOCKED |

## 5. G0–G8 assurance gates: decision logic

**G0 identity/release:** current PR HEAD and protected base SHA must be recorded; source manifest exact; package/import/CLI/release version aligned. All mandatory checks are required on the **same** verified source, not an unverified synthetic merge checkout. Historical `v0.2.0` may not be overwritten to disguise divergence.

**G1 shell/trust:** at least one original counterexample and benign twin for FC-01–09, explicit unknown/limit behaviors, no uncaught `IndexError`/`RecursionError`, no claim to fully interpret Bash. Preserve original independent finding detections.

**G2 cross-view:** negative conclusions require complete compatible observations; concurrency and vanishing inputs are `PARTIAL` or appropriate limitation. At minimum compare full protocol/family/bind address/port and prove ephemeral socket discrimination, namespace-aware scope and non-disclosure of raw local addresses.

**G3 offline:** all filesystem references rooted in authorized image; fail closed on links, missing metadata, unreadable package DBs and capped enumerations. Validate on a representative real image, distinct from toy fixtures. Record image hash, read-only mount options and legal permission before inspection.

**G4 mutations:** run strict changed-line and whole-package mutation measurement. Report counts `KILLED`, `SURVIVED`, `NO_TESTS`, `TIMEOUT`, `ERROR`, `NOT_RUN`, and any precisely justified equivalents. Every non-equivalent security-critical survivor must be killed by a test or eliminated by a sound implementation repair. No `# no mutate` blanket equivalence. Any incomplete budget or execution is non-PASS; don't hide it by redefining the denominator.

**G5 evidence:** every required generator/tool exit code observed and preserved; no stale coverage result accepted after a failed `coverage run` or JSON export. Exact `git HEAD`, source/test/workflow fingerprint, runtime version and CI receipt linked together; corrupt/missing/failing-tool controls MUST make the gate fail. A SHA256 alone does not authenticate authorship.

**G6 security/provenance:** check authenticated GitHub branch policy, expected check identities, release signing trust root, SBOM validity, artifact attestation signature and subject digest/commit/workflow, and private vulnerability reporting. A GitHub action configured in YAML is not evidence that a signed release exists or has been verified by a consumer.

**G7 empirical detection:** preregister a representative, independently labeled and separated positive/benign corpus with explicit sampling frame, threat-family and environment strata and time window. Report TP, FP, FN, TN, recall/sensitivity, precision (base-rate-aware), FPR per benign observation and false alarms per host-day, uncertainty intervals, confidence by strata, error budget and detection-delay distribution. No "100% accuracy" from synthetic fixtures. Store sensitive examples outside git and public CI; safe fixture summaries/digests only.

**G8 representative environments:** controlled authorized root system-scope scan in disposable host; real RO-mounted offline image; repeatable build/test on each claimed supported environment/OS/Python; independent challenge. Document unsupported kernel/OS cases, power/performance bounds, rollback and non-invasive collection. Self-review by the same agent does not count as independent external assurance.

A gate may use `PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_RUN` or a narrowly scoped `BLOCKED_EXTERNAL` status. Only `PASS` satisfies the assurance claim; a still-blocked external gate must never be disguised as code completion.

## 6. Exact evidence record per FC

For every candidate closure, store or link an immutable **non-sensitive** receipt that contains:

- `fc_id`, original audit SHA, `source_path`, priority, dependency closure, candidate code/test tree hash, target commit SHA;
- causal hypothesis, exact original `falsifier`, benign comparator and declared scope;
- negative control: altered/faulty source SHA (or isolated mutant ID), deterministic command, expected and observed red result with reason;
- candidate positive: exact command and environment, green result, limits/variance and input fixture digest;
- relevant changed-line and whole-package mutation result; a surviving mutant ledger with explicit disposition;
- full CI URL and run/job/check IDs, commit SHA asserted by checkout, result of coverage, tests, static analysis and evidence receipt;
- measured CPU, wall time, peak RSS and any resource-bound regression if applicable;
- residual risk, sample/population boundary, missing proof; reviewer/independence level;
- final `PASS/FAIL/BLOCKED/INCONCLUSIVE` with cited evidence. A mere PR comment or synthetic-green CI is insufficient.

If a record is committed in the same repo, avoid a self-referential commit-hash paradox: record the code commit and its content fingerprint, commit the evidence index afterward and **rerun checks on that final HEAD**. Never write the current commit SHA into its own preimage or pretend the index commit and candidate-code commit are identical.

Possible safe receipt location: GitHub Actions artifacts named with the exact observed commit SHA, linked from `tasks.json`. If introducing a new persistent non-sensitive evidence file, first extend the release allowlist intentionally, add negative packaging tests and update the source manifest.

## 7. Mandatory commands and reproducible workflows

The expected runtime is **Python >=3.10, standard library only**; CI dev tools are separately pinned in `pyproject.toml` / workflows. Do not add runtime dependencies without a documented nonoptional need and an SCA/provenance audit. Use isolated venv, inspect tool versions and ensure test skips are explained.

Run from repo root:

```bash
git fetch origin
git status --short
git rev-parse HEAD
gh pr view 19 --json headRefOid,baseRefOid,state,mergeStateStatus
(cd docs/verification/source && sha256sum -c AUDIT_CHECKSUMS.txt)
python assurance/check_registry.py
python -m unittest discover -s assurance -q
python tools/build_release.py --check-manifest
FALSICORE_REQUIRE_HYPOTHESIS=1 python -m unittest discover -s tests -q
python -m tools.evaluate_rules
python tools/validity.py --check
python tools/code_audit.py . --fail-on high
python -m ruff check --select F,E9,B,PLE falsicore tools falsicore.py
python -m bandit -q -r falsicore tools falsicore.py -c pyproject.toml
python -m mypy
python -m coverage run --branch --source=falsicore -m unittest discover -s tests -q
python -m coverage report -m --fail-under=88
python tools/mutate.py --coverage
python tools/mutate.py --diff origin/main --workers 2 --timeout 120 --json mutation-diff.json --markdown mutation-diff.md
python tools/mutate.py --all --workers 4 --timeout 120 --json mutation-full.json --markdown mutation-full.md
python tools/release_receipt.py --output /tmp/falsicore-release-receipt.json
python tools/release_receipt.py --check --output /tmp/falsicore-release-receipt.json
```

These commands are hypotheses until actually run on the current checkout. For source/test changes, regenerate the manifest with `python tools/build_release.py --write-manifest` before the check. Some checks require optional dev dependencies installed in an isolated venv. Mutation-full can be computationally expensive; choose a documented budget and checkpoint/resume, but a partial result is **NOT_RUN/BLOCKED**, never PASS. Run full audit and artifact tests again after a late patch.

Also verify same-source portable `.pyz` + full ZIP produced twice, compare archive bytes/hashes, run packaged `verify-app` and `self-test` outside the source checkout; ensure portable policy tests skip only repository-exclusive metadata, while real checkout CI does **not** skip it.

## 8. Operational performance and measurement plan

Before optimizing, declare a fixed, immutable workload matrix:

- benign current-user quick and standard profiles;
- bounded deep package-integrity work on dpkg, rpm, pacman and apk fixtures and authorized real images;
- adversarial large logs, many PIDs/TIDs, numerous sockets, truncated `ss`, corrupted metadata, symlink traps, limited permissions, slow/missing tools;
- positive threat shapes and benign lookalikes with correct ground truth;
- one-system and cross-platform reproducibility and startup/shutdown/timeout resilience.

For each workload record OS/kernel, CPU, cores, RAM, filesystem class, Python version, tool versions, seed, input SHA256, host/environment scope, permissions, warm/cold cache and N >= 10 runs where inexpensive; report median, p95/p99 where sample size supports them, peak RSS, CPU time, I/O, throughput, missed observations, skips, errors, FD leaks and output determinism. Predeclare concrete acceptance budgets **after** measuring a baseline; no arbitrary "3x faster" from one anecdote. Any speed win that suppresses coverage, weakens trust checks, hides errors or leaks private data is a regression. Benchmark the expensive PID sweep, package digest indexing, journal parsing, socket reconciliation and mutation selection independently.

## 9. Security, dependency and supply-chain discipline

- No default root, network connection, persistence installation, `curl|sh`, or host mutation in FALSICORE scanner code. Probe allowlist must be read-only; process groups and descriptors must be cleaned after timeout.
- Threat-model hostile input: malicious shell content, path traversal, symlink ancestor, ambiguous namespace, mounted-image race, malformed package DB and malicious output from supposedly trusted helper tools.
- Review pinning of every development/CI dependency and GitHub Action SHA; compare SBOM against actual build, and enumerate exposed OS/system tool prerequisites. Treat runtime `dependencies=[]` as a constraint. Inspect supported Python 3.10–3.14 and build/CLI/SDK import surfaces.
- `ruff`, `bandit`, `mypy`, CodeQL, unit tests, property tests and mutation tests are **independent incomplete instruments**. A red scan must be fixed at the causal source, not suppressed or ignored with an unexplained blanket exception.
- No public publishing of raw incident data or exploitable malware samples; conduct dynamic threat validation only inside consented, isolated and disposable environments.

## 10. Pre-merge decision and logically post-merge release evidence

**Current owner delegation permits Codex to merge PR #19 only after an objectively reviewable preflight**; older "owner-only" text in historical PR comments remains a timestamped record, not the latest authorization. No automatic immediate merge, `--admin` bypass, force push, disabling required checks, tag rewrite or merge of other PRs.

Required pre-merge proof:

1. Frozen original audit integrity validates; the 39-item register has no undocumented open risk or inflated `PASS`. Every applicable implementation/field requirement has current, reproducible proof, including genuinely external claims where requested. All G0–G8 pre-merge applicable criteria satisfied; `BLOCKED_EXTERNAL` is never equivalent to PASS.
2. Exact **final PR head** SHA, clean working tree and protected **current main** base SHA verified; no drift between the attested candidate and the actual merge target. Re-run after the last commit, not only an ancestor.
3. Every required `verify` Python matrix, `static-analysis` (including evidence dependency), `mutation-diff`, CodeQL, provenance/preflight, packed self-test, security and robustness gate is successful on the final SHA with unambiguous source. No `pending`, `cancelled`, `skipped`, `neutral` or missing status used in place of a mandatory result.
4. Zero unresolved known critical/high defect; every non-equivalent security-critical mutant killed, all incomplete mutation measurements explicitly blocked, no unproved waivers. Coverage and time budgets have actual measured rationale, and field results have documented limits.
5. Branch protection and required check *enforcement* established from authenticated GitHub API or owner/admin evidence. No direct `main` push or bypass.
6. Source/artefact digest agreement, reproducible candidate build, pinned dev dependencies, SPDX SBOM validated, **signed candidate build attestation** verified with a trusted identity and exact subject and commit, operational installation/rollback guide reviewed.
7. Release-only facts that logically require post-merge `main` (new tag target and public release assets) have a rehearsed, fail-closed post-merge procedure. These remain `PENDING_POST_MERGE`, **not PASS**, until executed; there is no claim of release readiness before the signed release is verified. If the original assurance contract explicitly requires the published release *before code integration*, record that circular dependency as a blocker rather than claiming it solved.

If all admissible pre-merge conditions hold, issue the actual normal PR merge using authenticated GitHub CLI/API **without bypassing branch policy**, retaining provenance and preserving the historical audit. Afterward, verify `main` HEAD, required CI and ancestry. Select a **new** compatible version/tag (never rewrite historical `v0.2.0`) if release policy permits; publish only from protected `main` after verified tag signing and exact-current-main checks; run consumer-side `gh attestation verify` against actual uploaded ZIP/pyz, validate SBOM and source digests. Only then convert post-merge release prerequisites to `PASS` and make an appropriately scoped operational release claim. If any step fails, stop, document and remediate; no fabricated rollback and no claim that a partially published release is valid.

## 11. Current recorded blockers at handoff (stale once new HEAD is observed)

- PR source checkpoint `e78adaa368b4d5c3f73cadff83109762b6f4c378`; **not an assurance-accepted SHA**. PR state OPEN / not merged as observed.
- Current `verify` run [#41290345980](https://github.com/neuron7x/falsicore/actions/runs/41290345980): Python 3.10/3.12/3.13/3.14 tests **PASS**; `evidence` **FAIL** with exact `RECEIPT_NOT_VERIFIED: static:bandit`; `static-analysis` consequently FAIL on the required evidence dependency; `mutation-diff` was running at time of inspection. [CodeQL #41290345990](https://github.com/neuron7x/falsicore/actions/runs/41290345990) PASS. First wave: retrieve and inspect the **artifact** of failed evidence and actual Bandit report, distinguish real high-severity issue from policy/config/tool error; repair cause with negative tests. Do not weaken the security gate.
- Latest completed older changed-line mutation report on `fbc61da7231cc9d41f3dd27f90976fef765ba234`: **393 generated, 346 killed, 47 survived, FAIL** ([run #41286842056](https://github.com/neuron7x/falsicore/actions/runs/41286842056)). This is historical, **not** the current mutation count. Root `# no mutate` blanket waivers were later removed; there is still no independently completed whole-package acceptance.
- `main` public branch metadata indicated protection enabled but named required checks did not include `evidence`; PR's current `static-analysis` depends on `evidence`. Verify actual administrator protections/enforcement, including bypass permissions, separately.
- Historical [`v0.2.0`](https://github.com/neuron7x/falsicore/releases/tag/v0.2.0) annotated tag points to `70ed7107bcd6c43a66b4e4cb59db25ee1b3a8516`; GitHub verification was `verified=false`, `reason=unknown_key`. No overwrite or retroactive certification.
- Canonical 39-item register at handoff: **27 IN_PROGRESS, 11 BLOCKED, 1 FAIL, 0 PASS**. These statuses are intentionally not claims that 27 are close to done. FC-31–36, 37 and 39 require real external evidence not present in synthetic tests.

## 12. Verified primary references (requirements, not certification)

| Source | Verified reference | Purpose and epistemic limit |
| --- | --- | --- |
| OpenAI Codex guidance | https://developers.openai.com/blog/rethinking-skills-and-prompts-for-gpt-6-astra | Keep root AGENTS.md concise and task-relevant; avoid bloated context. Guidance is not correctness proof. |
| NIST SP 800-218 SSDF v1.1 (final) | https://csrc.nist.gov/pubs/sp/800/218/final | Secure software development, vulnerability prevention and traceable remediation. |
| NIST SP 800-61 Rev.3 (final, 2025) | https://csrc.nist.gov/pubs/sp/800/61/r3/final | Incident-response scope and evidence discipline. |
| NIST SP 800-86 (final, 2006) | https://csrc.nist.gov/pubs/sp/800/86/final | Forensic acquisition, provenance and data-source boundaries. |
| OpenSSF OSPS Baseline v2026.08.28 | https://baseline.openssf.org/versions/2026-08-28 | Project security controls, secure build, branch policy and release authenticity; Level 1 applies to any project, Level 2 assumes multiple maintainers. |
| SLSA specification v1.2 (approved) | https://slsa.dev/spec/v1.2/ | Source/build provenance tracks and verifiable claims; no level is asserted without evidence. |
| GitHub artifact attestations | https://docs.github.com/en/actions/concepts/security/artifact-attestations | Signed build provenance vs mere digest; verification is necessary. |
| GitHub protected branches | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches | Required checks, signed commits, bypass and protection semantics. |
| OpenAI Codex repository instructions | https://developers.openai.com/cookbook/examples/codex/iterating-development-workflows-with-codex | `AGENTS.md` is recognized as persistent repository guidance, not an execution trigger. |
| Existing FALSICORE reference index | [`docs/BIBLIOGRAPHY.md`](BIBLIOGRAPHY.md) | Prior literature and tool-specific citation provenance; independently recheck any dated/current claim. |

Do not claim NIST/SLSA/OpenSSF or US-industry certification. Use their *specific control and test implications*, document applicability, and keep conclusions within demonstrated empirical bounds.

## 13. Required final output (only after genuine closure)

Produce a compact integrated evidence summary and linked artifact index: final PR merge commit SHA, code/test/manifest hashes, 39-item closure ledger, G0–G8 result matrix, all required green checks at exact source commit, survivors resolved, representative-host/field and independent challenge result with limitations, benchmark delta, archive reproducibility, signer-validated SBOM/attestation, and post-merge release version. If something is still missing, say **NOT READY** and enumerate the smallest missing evidence. The owner requested completion, not a theatrical statement of completion.
