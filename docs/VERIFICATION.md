# Release verification contract

A release is accepted when **the delivered artifacts** pass the checks below,
not merely the development checkout. Each claim is bounded by the environment
it was measured in.

## Required checks

1. `sha256sum -c SOURCE_MANIFEST.sha256` and `tools/build_release.py --check-manifest`. The manifest covers the tool (code, tests, tools, docs, root files). The `.github/` automation files are covered by the full distribution's `SHA256SUMS`.
2. The full suite passes, with discovered, passed, failed, errored and skipped
   counted separately. Every earlier regression-test file is kept.
3. Branch-aware coverage of `falsicore/` is reported with its denominator and
   no exclusions. The CI gate is 88%.
4. Targeted fault injection: each changed protection is removed in an isolated
   copy, and the relevant tests must fail.
5. Two `build_app.py` builds and two `build_full.py` builds of the same
   snapshot are byte-identical.
6. The full ZIP is extracted into a fresh directory whose path contains spaces
   and Cyrillic, and these all pass there: `sha256sum -c SHA256SUMS`, the
   launcher hash check, `verify-app`, `self-test`, the embedded source
   manifest, a user-scope scan, and `verify` of its report.
7. A tampered or extra member in the `.pyz` is refused before any scan.

## Where the results are

- `docs/AUDIT.md`: defect register, gates, coverage, limitations.
- The release receipt next to the ZIP (`*.zip.sha256`), plus
  `verification/` inside the ZIP: tool versions, commands, exit codes,
  counts, durations. Host observations are never included.

## Boundaries

- Measured on Ubuntu 24.04.4 with Python 3.12.3 (host, UID 1000).
  Python 3.10, 3.13 and 3.14 are exercised only by hosted CI, and are claimed
  only once that run is observed.
- No system-scope (root) scan was performed for this release.
- A checksum is not a signature. An attacker who controls the kernel, or the
  tool and its manifests, can forge internally consistent observations.
- The internal AST checker is a supplementary pattern audit, not a
  vulnerability scanner. Bandit and CodeQL are the established analysers.
- Python's `zipapp` and `shlex` documentation describe mechanisms; they do not
  certify this application.
