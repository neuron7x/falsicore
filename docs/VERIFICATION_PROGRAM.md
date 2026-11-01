# FALSICORE verification and remediation program

**Status:** proposed requirements; all G0–G8 below are **NOT_RUN** in this program. This document does not fix the findings or certify a release. The source act `FALSICORE-VA-2026-11-01` concerns commit `41745142378ccab363974db9f3cd568188706524`. Its classifications are audit claims, not independent re-execution. Re-establish the current state before relying on them. `RELEASE-ASSURANCE HOLD` means the assurance claim is unavailable; a separately labeled experimental build may still be distributed with its actual limitations.

## Scope and epistemic rules

The program covers every FC-01–FC-39 item in the companion verification registry. Preserve the original act, finding identifiers, historic evidence and negative results. `SC` is a source-review claim; `RR` identifies a counterexample reproduced in a previous review, not necessarily independently on the current commit; `EG` is missing evidence, not proof of a defect; `FX` describes a historical fix, not an active finding. A closed review thread, a self-reported metric, a green workflow, a signature, or a checksum alone does not establish any stronger claim. Reopen a closed item if its falsifier recurs or its evidence is invalidated.

Three separate claims require separate evidence: implementation conformance to a stated contract, correctness of the measurement and release machinery, and detection validity in a defined operational population. Coverage, fixture scores and a clean test suite do not prove field detection effectiveness, host cleanliness, or trustworthy observations from a compromised kernel.

## Invariants

1. **Incomplete observation:** for each declared essential check, an absence-based verdict is permitted only when the check's observation is complete within the stated scope. An unavailable, truncated, timed-out or untrusted observation must carry its own limitation and cannot become evidence of absence. Confirmed findings remain visible even if another check fails.
2. **Trust identity:** a basename, a packaged executable or a package database digest does not establish the identity or trustworthiness of arbitrary input or execution output. Bind trust decisions to the exact object, input, context and qualified source.
3. **Execution provenance:** associate taint with the actual evaluated operand and parse nested executable syntax or explicitly report a limitation. Parser limits must bound depth, time, memory and resulting coverage.
4. **Comparable views:** cross-view absence inference requires compatible namespaces, privileges, address families, endpoint identities, timestamps and sufficiently complete observations; otherwise record the gap. Confirmation must handle legitimate transient state.
5. **Offline boundary:** reads and subprocesses must remain inside the declared image root, including ancestor symlinks and races, or decline the observation with a named limitation. Never substitute live-host evidence for image evidence.
6. **Measurement integrity:** every required command and input is bound to the examined state and a verifiable receipt. Missing data, unexpected skips, unexecuted mutants, unjustified waivers, failed static checks and partial output cannot pass by truthiness or omission.
7. **Bounded claims:** no findings means only no configured indicators observed within accessible scope. Build reproducibility is bounded by its actual build matrix; synthetic metrics are bounded by their corpus.

These invariants are requirements to verify, not claims that the present implementation satisfies them.

## Gate model and dependency order

Each gate has `PASS`, `FAIL`, `INCONCLUSIVE`, or `NOT_RUN`. `PASS` requires every applicable criterion and complete, current evidence. `FAIL` records a demonstrated violation; `INCONCLUSIVE` records an attempted but insufficient measurement; `NOT_RUN` records no measurement. Missing, malformed, stale or untrusted evidence is never `PASS`. A gate may depend on others, but one gate's green result cannot imply another's. The assurance claim requires all applicable G0–G8 to pass on the same defined release state. A planned exclusion must narrow the claim explicitly, never silently convert a required gate to pass.

| Gate | Findings | Required acceptance evidence; all presently NOT_RUN |
|---|---|---|
| G0: identity and release | FC-20, 21, 24–28, 38 | Source, tests, version, tag and release assets agree; required gates and provenance bind the same release. Verify actual branch restrictions and signing trust, not configuration intent. |
| G1: shell and trust | FC-01–09 | Positive, benign and unsupported cases for each construct; operand-specific provenance, executable identity and bounded parser behavior. Independent regression and faulty-control evidence per finding. |
| G2: cross-view | FC-10–13 | Scope-aware hidepid, transient and stable observations, truncated-command outputs, family/address identity. Incomplete or incomparable data must not yield a hiding claim. |
| G3: offline | FC-14–16, 30 | Realistic image and adversarial path/metadata fixtures; preserve package failures, explicitly account for omitted records and prove containment or report uncertainty. |
| G4: mutation measurement | FC-17–19, 23, 29 | No-op source roundtrip, continuation-line selection, budget exhaustion and waiver negative controls; per-mutant ledger, exact equivalence rationale and unresolved survivor policy. |
| G5: evidence regeneration | FC-21, 22, 24, 38 | Stale, corrupt and missing input tests; independent remeasurement; every required failing measurement blocks success; eliminate self-referential regeneration dependency. |
| G6: security and provenance | FC-27, 28, 37, 39 | Independently verify repository policy and disclosure configuration; verify asset digest, identity-bound signed provenance and applicable SBOM with documented trust roots. |
| G7: empirical validity | FC-31, 32 | Preregistered scope and sampling, independent labels and held-out representative population; confusion counts, intervals, base-rate assumptions and time-to-detection distributions. |
| G8: representative environments | FC-33–36 | Disposable privileged host, provenance-verified read-only mounted image, defined cross-platform build matrix and independent external challenge; each result has its own scope and limitations. |

Sequence the work as follows: (1) establish provenance and safely reproduce current observations; (2) repair safety-critical G1–G3 behavior while preventing evidence-loss regressions; (3) establish trustworthy G4–G5 measurements and G0/G6 release controls; (4) execute G7–G8 as resources and independent evidence permit. G0 cannot pass merely because later work is planned. Some investigations and tests can proceed in parallel; acceptance remains bound to a common release state.

## Finding lifecycle and test protocol

For each FC identifier, record owner, priority, target scope, source evidence and audited SHA, current status, dependencies and next falsifier. Assign one accountable maintainer; independent verification should be performed by a different reviewer or independently replayed process when available, with the independence level recorded. A solo maintainer may run the process without falsely claiming independent external review.

1. Freeze the candidate source and record revision, tree, clean/dirty state and environment. Read the original finding and review thread; record whether the original claim can still be observed. Preserve a negative or inconclusive reproduction result.
2. State the smallest behavior contract and falsifier before implementation. Add a regression covering the failure and a nearby benign or unsupported case. Use boundary, property-based, fault-injection or mutation checks when they test the actual invariant; specify time, memory, output and skip budgets before running.
3. Run a negative control against an isolated deliberately faulty version and show the new test fails for the intended reason, not for formatting, setup failure or an unrelated exception. Restore the correct candidate and show the same test passes. Record both result streams and source hashes. Never mutate the original checkout or production evidence.
4. Run applicable focused, integration and required release checks without weakening gates. Record exact test inventory, skipped/partial outcomes, inputs and logs. Resolve each non-equivalent critical survivor; equivalence waivers identify one mutant, rationale, reviewer and evidence, not an entire source line.
5. Independently replay on the same candidate state and compare the receipt with the evidence. Close only with a current passing result, control failure, applicable gate evidence, explicit residual risk and a durable evidence reference. For EG, close only with the missing evidence itself or retain an explicitly narrower claim; do not relabel an absence of evidence as a defect or success.

Existing tools include `tools/gate.py`, `tools/mutate.py`, `tools/validity.py`, `tools/release_evidence.py` and `tools/build_release.py`. They represent present implementation, not the proposed new gates above. The act identifies potential defects in measurement and release tools; their success alone is not sufficient to close FC-17–25 or FC-38. Check command options and dependencies in the pinned revision before use. The `python3 assurance/check_registry.py` intake validator checks the original finding digest and registry consistency only; it does not validate receipts, reproduce findings or establish gate outcomes. Receipt verification and branch policy controls do not yet exist merely because this document requires them.

## Receipt and provenance contract

The following is a proposed receipt specification, not a generated attestation. Each result must retain at least:

- claim, gate and FC identifiers; outcome and incomplete reason codes;
- repository URL, full commit SHA and tree SHA, submodule/dependency state, clean/dirty status, binary diff hash and untracked-input manifest hashes; a dirty run is a distinct candidate and cannot be attributed to the clean commit;
- immutable input inventory and SHA-256 hashes for source, tests, datasets, build configuration, dependency lockfiles, toolchain and relevant scripts; document exclusions and why they cannot affect the claim;
- command arguments, working directory, non-secret environment parameters, OS/kernel/architecture, interpreter and tool versions, timestamps, exit status, timeout and resource limits;
- test inventory, executed/passed/failed/skipped/not-run counts, mutant identities and dispositions, raw logs, negative-control identity and result;
- output artifact hashes, evidence locations, identity and trust-root verification results, scope, limitations, and reviewer/verification method.

Hash canonical raw bytes and record encoding and inventory rules. Logs must not expose credentials or private incident data. Artifacts, test logs and source snapshots must remain retrievable, including failed results. A checksum proves byte integrity relative to a trusted reference, not authorship or a trustworthy build. Independently authenticate signer keys and verify attestations against expected source, builder, subject digest and trust policy.

**Avoid the self-reference trap:** a committed document cannot contain the hash of its own final commit or a digest that includes itself. Produce a separate post-commit receipt from the exact immutable commit and its defined input set, store it externally or as an independent signed release attestation, and bind it to artifact digests. If a checked-in evidence template is used, explicitly exclude it from the self-hashed input set and validate the exclusion. A subsequent commit produces a new candidate and invalidates prior exact-commit evidence unless a claim is expressly scoped to unchanged immutable inputs.

## Safe environments and reproducibility

Run ordinary tests without elevation in an isolated, disposable checkout. Capture provenance and an initial read-only image hash before mounting; use a read-only mount and prevent host access, network egress and accidental writes according to a documented VM isolation policy. Do not execute samples, inspected files or compromised images on the workstation. When privileged kernel behavior is necessary, use a disposable VM with scoped privileges, snapshot restoration, command audit and explicit containment; record unsupported observations rather than assuming isolation succeeded. Compare image hashes after use and retain mount configuration, isolation results and teardown records. No production system is an experimental corpus.

For builds, preregister platforms, Python and toolchain versions, dependencies, archive metadata, environmental controls and the expected byte-identical or explicitly platform-specific output contract. Build independently in the declared matrix; compare artifact digests and investigate discrepancies. Same-host repetition establishes only the tested setup, not cross-platform equivalence. Preserve failed builds, not just successful receipts.

## Operational validity protocol

Before collecting outcomes, specify deployment population, incident definition, unit of analysis, time horizon, observation window, admissible interventions, inclusion/exclusion criteria and expected ground-truth process. Separate development and held-out evaluation by host, incident and time as needed to prevent correlated leakage. Document representativeness, selection and survivorship bias, missing labels, uncertain or disputed ground truth, duplicate incidents, dataset provenance, sampling method, changes over time and out-of-distribution limits. Independent labelers should be blinded to detector output where feasible; report disagreements and adjudication.

Report `TP`, `FP`, `TN`, `FN` with denominators and unit, recall `TP/(TP+FN)`, false-positive rate `FP/(FP+TN)`, and precision `TP/(TP+FP)` when denominators permit. Report time-to-detection with censoring and observation-window rules; distinguish host-level and event-level rates. Prespecify confidence intervals and account for dependent or clustered samples; do not extrapolate a random-sampling interval to a convenience fixture set. With assumed independent representative negatives only, zero false positives in `n` trials has exact one-sided 95% upper bound `1 - 0.05**(1/n)`; this is not a field claim for the synthetic fixtures. For prevalence `p`, conditional positive predictive value is `TPR*p / (TPR*p + FPR*(1-p))` only under the specified population and stable conditional rates; report assumptions and undefined cases. The absence of a representative corpus remains `NOT_RUN` or `INCONCLUSIVE`, never an inferred pass.

## Release, rollback and governance

A release candidate is immutable: identify the exact tag target and source tree, enumerate required checks and build outputs, verify version consistency and each artifact subject digest, and independently verify provenance and security policy. A release cannot inherit a prior green result after any relevant source, test, dependency, tooling or policy change. Publish claim boundaries and known limitations with an experimental build. Do not claim an assurance-grade release while a required gate is failed, inconclusive or not run. Record the actual branch protections and private vulnerability reporting setting with an authorized maintainer-provided receipt; unavailable administration access is an explicit gap, not a pass.

On a discovered regression or provenance failure, stop the affected release claim, preserve the original artifact and evidence, assess user impact, communicate through the established disclosure process and publish a corrected immutable version. Revoke or supersede affected attestations when supported; do not silently replace assets under the same identity. Verify the rollback and correction as new candidates, including regression and negative control. Private vulnerability information and production forensic data must not be placed in public issue or evidence records.

## References and applicability

- [NIST SSDF publications](https://csrc.nist.gov/Projects/ssdf/publications): SP 800-218 v1.1 is final; the v1.2 revision has been published as a draft. Use as secure-development guidance; assess each applicable practice separately.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and [SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final): incident-response and forensic evidence guidance; neither certifies this implementation.
- [OpenSSF OSPS Baseline v2026.08.28](https://baseline.openssf.org/versions/2026-08-28): source-control, CI isolation and vulnerability management practices; assess the applicable maturity level and actual repository settings.
- [SLSA v1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements): build provenance and progressively stronger build controls; a signature or SBOM alone does not establish a SLSA level.

These are design references and proposed requirements, not claims of compliance, certification or external endorsement. Recheck standard versions when executing the program.
