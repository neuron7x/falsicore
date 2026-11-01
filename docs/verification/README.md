# Verification act: source and task register

The [task register](tasks.json) maps all 39 positions in the supplied
[FALSICORE verification act](source/FALSICORE_VERIFICATION_ACT.md) to a
falsifier, acceptance condition, evidence link, dependency IDs and execution
state. It is a work backlog, not evidence of remediation or release readiness.
Each task starts `NOT_RUN`: that state records work on this register, not a
claim that the original auditor did not inspect source or reviews. Reproduce
against the precise candidate source revision before updating a task. Record
failed and inconclusive runs alongside any successful run. The listed
dependencies are proposed technical prerequisites, not proof that other tasks
are unaffected.

The act attributes the observations to upstream commit
`41745142378ccab363974db9f3cd568188706524`. Treat them as dated, bounded
assertions, not findings independently reproduced by this register. It
separately identifies four historical source fixes; these are retained in
[`source/FINDINGS.json`](source/FINDINGS.json) as `historical_fixed`, and are
not counted as active tasks.

`SC` means source-confirmed in the act; `RR` means an earlier review reported a
reproduction; `EG` means an evidence gap and does not establish a product
defect. `P1` and `P2` are triage labels, not CVSS assessments. A task's
`falsifier` is copied verbatim from the supplied machine-readable act;
`falsifier_en` is an explanatory English paraphrase and `acceptance` is a
work criterion. In case of discrepancy, the source act governs until reviewed.

## Provenance and integrity

The supplied bundle bytes are preserved in [`source/`](source/). Its original
`SHA256SUMS.txt` is named `AUDIT_CHECKSUMS.txt` here to avoid a collision with
the release builder's generated checksum-file convention; its bytes are unchanged.

| File | SHA-256 |
| --- | --- |
| `FALSICORE_VERIFICATION_ACT.md` | `d79235631d2a4851c6c065b9ca969634848c87e4d93b1e096e63d782a36e0c39` |
| `FINDINGS.json` | `cbc6c13f491f6cc8a927faa5abd9ddf55fd7a04ccecc26ef48389aa67890d141` |
| `README.txt` | `bb21c84043f4e879993eedfc089d882720d2efc8807a8d5d2e8062194b4391d7` |
| `AUDIT_CHECKSUMS.txt` | `0ecc0d5406743184c291cf9d620c709ae00e8f883afca82835f523d96e510b05` |

The provided checksum file covers the act and findings JSON. It verifies byte
integrity against that supplied manifest; neither these hashes nor the copy
establish authorship, publisher identity, original acquisition provenance, or
the truth of the act's claims. The local supplied bundle is the acquisition
source for this register.

Verify the copied act and JSON from the `source/` directory:

```sh
sha256sum -c AUDIT_CHECKSUMS.txt
```
