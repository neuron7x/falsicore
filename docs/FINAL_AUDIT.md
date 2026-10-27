> HISTORICAL: this document records the 0.1.0 audit, not the current release.
> Current evidence is docs/RELEASE_EVIDENCE.json and docs/VERIFICATION.md.

# Canonical release audit — FALSICORE 0.1.0

## Audited object and epistemic status

Independent review of the **source tree and resulting Linux ZIP artifact** on 2026-10-27. Reviews were conducted in separated architecture, adversarial-regression, and reproducible-release passes, **not by independently deployed human auditors or multiple external AI agents**.

This audit verifies **implementation and distribution properties**, not malware-detection effectiveness or endpoint innocence. No owner-machine access was available. All endpoint findings in tests are synthetic; live container smoke evaluates execution plumbing only.

## Release blockers found and disposition

| Finding | Severity | Reproducer | Corrective control |
|---|---|---|---|
| Direct child exited while grandchild held inherited stdout: false `COMPLETED` | High | `test_v32_assurance.ProcessLifetimeTests` | Require direct-child exit **and** stdout EOF; kill group on deadline/output cap |
| Process closed stdout but kept running: could be killed or misclassified early | High | `test_final_hardening.ProcessCompletionContracts` | Separate EOF and process-reap state machine |
| Manifest hashes alone could hide semantically contradictory report fields | High | `test_final_hardening.SemanticEvidenceContracts` | Recompute outcome, digests, counts and coverage gaps from stored report data |
| Missing Firefox/Chromium manifests and symlink profiles could report complete inspection | High | `test_final_hardening`, `test_fixture_collectors_final` | Mark as `PARTIAL`; never conflate missing telemetry with a negative finding |
| Nested directory traversal could skip permission errors silently | Medium | `test_final_hardening.MissingTelemetryIsNotNegative` | `os.walk(onerror=...)` materializes coverage gap |
| Shell/autorun/sudoers unreadability not reflected in persistence status | Medium | Synthetic fault paths and audit of source branches | Count inaccessible files and propagate `PARTIAL` |
| Generic allowlisted binary could be used with mutating arguments by a future collector | High | `test_release_contract_final.FixedReadOnlyAuditPolicy` | Separate exact read-only invocation policy for Audit commands |
| Release files were hashed and then read again for ZIP | Medium | `test_release_contract_final.AtomicDistributionContracts` | Single no-symlink source read per file; same bytes feed SHA-256 and ZIP |
| Existing release could be replaced by packaging | Medium | `test_release_contract_final.AtomicDistributionContracts` | Atomic exclusive hard-link commit; no overwrite |
| Stale source manifest after editing docs/test files | High release blocker | `sha256sum -c SOURCE_MANIFEST.sha256` | Regenerate manifest only as part of final release build; verify extracted ZIP |
| Three root-assuming tests failed on a normal Linux user; CI portability broken | High release blocker | `runuser -u oai -- python3 -m unittest discover -s tests -q` | Simulate UID explicitly in system-scope tests; run complete suite as root and non-root |
| Three packaging tests wrote into the source tree and required writable checkout | Medium | Same non-root cleanroom test suite | Move attack fixtures into isolated temporary directories |

## Release gate contract

- Unit/integration/adversarial tests: all pass, no skips or known failures.
- Static source audit: 9 pattern rules, zero high matches and zero parse gaps on own Python code.
- Fixture rule recognition: 9/9 positive, 9/9 negative synthetic cases. These ratios are **not** field detection performance.
- Branch-aware coverage: measured via Coverage.py; **not** a security assurance percentage.
- No network required for runtime; no root needed in `run.sh`; no execution of suspicious files.
- Report verifier rejects missing/modified/extra files and cross-file semantic disagreement; no publisher signing implied.
- ZIP reproducibility: two independent builds must have identical SHA-256, with source manifest exact from extracted bytes.
- Fresh extraction: test suite, executable permissions, syntax, quick/standard scan and `verify` from the ZIP (non-root).
- CI YAML parse and dependency manifest: reviewed locally; GitHub workflows **must run on GitHub before publishing as released**.

## Residual acceptance limits

1. Any privileged/root/kernel attacker can falsify host-observed telemetry and local proofs; trusted external-media acquisition is out of scope.
2. Lack of representative labeled malware/compromise test corpus: TPR/FPR, sensitivity, specificity and false-negative rate are **not measured**.
3. Static browser analysis neither tests current Instagram service security nor checks Meta server-side account sessions.
4. There is no independent, externally signed build provenance. SHA-256 verifies equality, not authorship.
5. The source-pattern analyzer implements nine intentionally narrow AST rules and does not replace CodeQL, taint analysis or dynamic instrumentation.
6. No real GitHub CI results exist until the owner pushes the repository and enables required workflows.
7. A 0.1.0 release can be operationally useful without satisfying formal certification or 100% test coverage.

## Methodological anchors

- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final): specification and implementation controls. The 1.2 revision is draft, not final (as of 2026-10-27).
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): incident response governance, not an endpoint detection algorithm.
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final): forensic evidence process and limitations.
- [MITRE ATT&CK](https://attack.mitre.org/): behavior hypotheses only where available telemetry supports the specific detection.
- [Microsoft SDL](https://www.microsoft.com/en-us/securityengineering/sdl/): threat modeling and repeatable verification.
- [OpenSSF OSPS](https://baseline.openssf.org/): code review, disclosure and automation.

**Acceptance:** a reproducible, self-contained **offline endpoint triage alpha** usable by a Linux owner. **Not accepted:** claims of guaranteed intrusion detection, complete forensic acquisition, all tests/coverage at 100%, or GitHub deployment already performed.
