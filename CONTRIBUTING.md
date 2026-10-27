# Contribution contract

Changes should be minimal, independently reviewable and supported by a regression test.

1. Reproduce the defect or formalize a rule; identify the observation and expected failure mode.
2. Preserve the offline/no-sudo default and never write into the inspected environment except private new reports.
3. Add tests for benign and suspicious cases. Do not use live exploit payloads or upload personal device evidence.
4. Run `make test source-audit rule-fixtures smoke` and verify report integrity on a private synthetic fixture.
5. Refresh the source manifest with `python3 tools/build_release.py --write-manifest`; commit `SOURCE_MANIFEST.sha256` only after reviewing the diff. Builds never modify the tree.
6. Explain the evidence limit in the pull request. A new detector must have its rule ID, severity, false-positive risks, and coverage assumptions recorded in `docs/DETECTORS.md`, and an entry in `falsicore/guide.py` (enforced by a test).

Contributions are accepted under the repository license (Apache-2.0, inbound = outbound). Do not submit third-party code whose license is incompatible. No unpublished incident data, credentials or full private report artifacts belong in issues or pull requests.
