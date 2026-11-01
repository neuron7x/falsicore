# FALSICORE Assurance Protocol (FAP-0.1)

**Purpose:** separate quality of implementation, integrity of artifacts, and effectiveness of threat detection. These are three different claims.

## Evidence hierarchy

| Claim | Minimum evidence | Release gate |
|---|---|---|
| Source code compiles | Python syntax validation | `compileall` PASS |
| Rules are internally consistent | deterministic positive and negative fixtures | `tools.evaluate_rules` PASS |
| Code changes preserve contracts | unit + negative + integration tests | `unittest` PASS |
| Source-pattern audit finds selected unsafe idioms | nine AST rules + fixture corpus | static audit without high findings or collection gaps |
| Distribution is reproducible | byte-identical independent ZIP builds | SHA-256 equality |
| Distribution is complete | source allowlist + exact manifest verification | no unexpected files and complete hashes |
| Collected report is internally coherent | SHA-256 manifest and semantic recomputation of outcome/counts/gaps/reason codes/baseline | verifier PASS, malicious rehash/inconsistency/baseline-edit regressions PASS |
| Tests guard the protections they claim to | targeted fault injection on an isolated copy | every mutant killed (docs/AUDIT.md) |
| Rules detect the artifact shapes they target and spare benign twins | hermetic fixture host, one planted shape per scenario, full scan (`tools/validity.py`) | every positive detected, every twin silent, unplanted host `NO_COMPROMISE_INDICATORS_OBSERVED`, committed table current |
| Endpoint is not compromised | representative labeled corpus, host event coverage, independent forensic analysis | **NOT ESTABLISHED** |

## Safety invariants

- Default execution never elevates privileges, opens external sockets, executes inspected files or changes existing system settings.
- Output remains local and private. No raw browser cookies, passwords, history, secret SSH keys or full journals are exported.
- An unavailable check cannot turn into evidence of safety.
- A failed collector must roll back its partial findings, derived baselines and statistics before reporting failure.
- Successful external command capture requires the direct process to exit zero **and** the output pipe to reach EOF; a descendant keeping the pipe open cannot spoof success.
- A collector may execute only exact predefined read-only argument shapes. Scheduler mutations require a separate explicit `monitor enable/disable` operation.
- Report self-verification checks both file-set hashes and internal semantic consistency. Neither is a trusted attestation or digital signature.
- Interpretations are deterministic functions of normalized observations, not random/LLM outputs.
- Filesystem reads reject symlink traversal through checked ancestors; privileged OS compromise remains out of trust boundary.

## Threat and standards traceability

| Source | Selected principle | Implemented control | Limit |
|---|---|---|---|
| [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (2025) | contain uncertainty in incident response | explicit verdict + gap reports | not an official NIST validation |
| [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final) | protect evidence provenance | separate collection and integrity manifest | no write-blocker / offline acquisition |
| [OpenSSF OSPS v2026.08.28](https://baseline.openssf.org/versions/2026-08-28) | source review, tests, vulnerability disclosure, delivery | CI, SECURITY.md, allowlisted release | no compliance certification; GitHub settings must be enabled manually |
| [Microsoft SDL](https://www.microsoft.com/en-us/securityengineering/sdl/) | threat-aware secure development | threat model, adversarial regressions | no external audit |
| [MITRE ATT&CK](https://attack.mitre.org/) | hypothesis-driven signal categorization | stable rule IDs and technique references | full ATT&CK telemetry not available |
| [MITRE CWE](https://cwe.mitre.org/) | well-defined source weaknesses | nine conservative AST checks | no comprehensive dataflow analysis |

Primary sources behind each row, verified against publisher pages, are in
`BIBLIOGRAPHY.md`; the table above names the control, the bibliography names
the reason.

## Measurement contract

- Test count = number of executable unit/integration cases that passed, **not** detection efficacy.
- Statement/branch coverage = percentage of measured implementation paths executed by tests, **not** logical correctness or attack coverage.
- Synthetic precision/recall apply **only** to the fixed artificial code-pattern fixture corpus; never generalize them to malware or unseen vulnerabilities.
- `NO_COMPROMISE_INDICATORS_OBSERVED` is bounded to the accessible data and configured rules.

The release evidence is in `RELEASE_EVIDENCE.json` and `AUDIT.md`; values apply only to the recorded testing environment. GitHub CI results are not asserted until observed on GitHub.
