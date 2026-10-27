# GitHub publication checklist — 0.1.2

This bundle contains a repository tree, not a completed GitHub deployment.

1. Create a **new** public repository named `falsicore` if available; verify trademark/name independently.
2. Use `python3 -I falsicore.pyz export-source "$HOME/falsicore-source"`, then upload the exported source contents, not private output directories, `.coverage`, logs, virtualenvs or `private_index.json`.
3. **Owner decision:** select a license before encouraging redistribution. Until then, no open-source permission is granted.
4. Enable GitHub Actions and **private vulnerability reporting**; inspect branch protection/rulesets and enforce the `verify` check. Solo author exceptions should be explicitly documented, not concealed.
5. Observe `verify` matrix and `CodeQL` directly on GitHub. These workflows are prepared but were not remotely executed by this release build.
6. Confirm GitHub workflow permissions. `verify` and `codeql` are read-only except for CodeQL's scoped `security-events: write`; only release on a `v*` tag can create a GitHub release.
7. Commit a reviewed, matching `SOURCE_MANIFEST.sha256`. Do not treat it as provenance. Use the trusted GitHub source and SHA file.
8. Tag **`v0.1.2`** only after CI is green. `release.yml` reruns checks, creates two byte-identical portable builds, and attaches `.pyz` + `.sha256` to a GitHub release.
9. Never post a real endpoint scan, path index, personal home paths or raw security logs in a public issue.

## Local commands before push

```bash
python3 -m unittest discover -s tests -q
python3 tools/code_audit.py . --fail-on high
python3 -m tools.evaluate_rules
python3 -m compileall -q falsicore falsicore.py tools
python3 tools/build_app.py /tmp/falsicore.pyz
sha256sum -c SOURCE_MANIFEST.sha256
```

After changing files, rebuild the source manifest and commit its new digest. Do not execute the ZIP as root simply because CI is green.

Suggested repository description:

> FALSICORE — deterministic offline Linux endpoint triage with evidence-bounded reporting and a conservative Python source auditor.
