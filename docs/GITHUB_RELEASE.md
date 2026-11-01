# GitHub publication checklist — 0.2.0

The repository is `neuron7x/falsicore` (public, Apache-2.0).

1. Push only the allowlisted tree; `tools/build_release.py` refuses anything else. Never push
   `.falsicore-audit/`, `.venv/`, `.coverage`, run folders or `private_index.json`.
2. Run `python3 tools/build_release.py --check-manifest` before committing. After changing
   files, run `--write-manifest` and review the diff.
3. Observe the `verify` matrix and `codeql` on GitHub before tagging. A workflow counts as
   passed only once its run has been seen.
4. Workflow permissions: `verify` and `codeql` are read-only, except CodeQL's scoped
   `security-events: write`. Only a `v*` tag runs `release.yml`, whose publish job
   alone gets `contents: write`.
5. Enable private vulnerability reporting and branch protection on `main` in the
   repository settings. These are manual settings and cannot be set from code.
6. Tag `v0.2.0` only after CI is green. `release.yml` rebuilds `.pyz` and the full ZIP
   twice, compares the bytes, and attaches the artifacts with their external SHA-256 files.
7. Never post a real endpoint scan, a path index, home paths or raw security logs in a
   public issue. Use `explain --share-safe`.
