# Contribution contract

Changes should be minimal, independently reviewable and supported by a regression test.

1. Reproduce the defect or formalize a rule; identify the observation and expected failure mode.
2. Preserve the offline/no-sudo default and never write into the inspected environment except private new reports.
3. Add tests for benign and suspicious cases. Do not use live exploit payloads or upload personal device evidence.
4. Run `python3 tools/gate.py` (everything CI runs, fails closed). A new or changed rule needs a positive scenario and a benign twin in `tools/validity.py`; refresh the table with `python3 tools/validity.py --write`.
5. Run `python3 tools/mutate.py --coverage && python3 tools/mutate.py --diff origin/main`: every mutant on a changed runtime line must be killed, or the line carries `# no mutate: <reason>` with a reason that shows equivalence.
6. Refresh the source manifest with `python3 tools/build_release.py --write-manifest` **from the exact file set you commit**; commit `SOURCE_MANIFEST.sha256` only after reviewing the diff. Builds never modify the tree.
7. Explain the evidence limit in the pull request: what the change claims, what would refute it, what was measured and where the number lives. A new detector must have its rule ID, severity, false-positive risks, and coverage assumptions recorded in `docs/DETECTORS.md`, an entry in `falsicore/guide.py` (enforced by a test) and an ATT&CK technique label. Refuted claims stay in `docs/AUDIT.md` with their disposition; negative results are never deleted.

Contributions are accepted under the repository license (Apache-2.0, inbound = outbound). Do not submit third-party code whose license is incompatible. No unpublished incident data, credentials or full private report artifacts belong in issues or pull requests.
