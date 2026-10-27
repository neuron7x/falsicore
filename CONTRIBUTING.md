# Contribution contract

Changes should be minimal, independently reviewable and supported by a regression test.

1. Reproduce the defect or formalize a rule; identify the observation and expected failure mode.
2. Preserve the offline/no-sudo default and never write into the inspected environment except private new reports.
3. Add tests for benign and suspicious cases. Do not use live exploit payloads or upload personal device evidence.
4. Run `make test source-audit rule-fixtures smoke` and verify report integrity on a private synthetic fixture.
5. Generate a fresh source manifest with `python3 tools/build_release.py /tmp/falsicore-verify.zip`; commit `SOURCE_MANIFEST.sha256` only after reviewing the diff.
6. Explain the evidence limit in the pull request. A new detector must have its rule ID, severity, false-positive risks, and coverage assumptions recorded in `docs/DETECTORS.md`.

**No license for external contributions has been granted by this repository.** Coordinate terms with the owner before contributing third-party code. No unpublished incident data, credentials or full private report artifacts belong in issues or pull requests.
