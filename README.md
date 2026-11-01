# falsicore

**Offline, read-only intrusion triage for a single Linux host, with explicit coverage.**

```bash
bash run.sh                     # standard profile, current user, ~2 s
bash run.sh --profile deep      # adds package integrity (dpkg/rpm/pacman/apk), ~60 s
```

---

## Abstract

falsicore inspects the running host for traces of intrusion and persistence:

- processes;
- network listeners;
- scheduled and start-up execution;
- browser extensions and native hosts;
- authentication logs (journald, or syslog files where journald is absent);
- package integrity (dpkg, rpm, pacman, apk);
- kernel state;
- cross-view consistency (hidden processes, modules, listeners, mounts over `/proc/<pid>`).

It never modifies the host or contacts the network. For every finding it
states the observation, the attribution, the benign alternatives, the
uncertainty, and a non-destructive next step. For every check it states
whether its defined target was fully inspected and, if not, why.

The design is falsificationist. The tool never asserts "clean": the absence of
findings is reported together with the exact scope in which they were absent.

## Claims and how to refute them

Each claim below is enforced by code and covered by tests.

| # | Claim | Refuted by |
|---|---|---|
| C1 | The scan never writes outside its private report folder, never invokes `sudo`, never opens a socket. | Any write, privilege change or connection during `scan` (see `tests/`, `docs/THREAT_MODEL.md`). |
| C2 | A check is `PARTIAL` **iff** it carries an incompleteness code. Scope limits are reported separately and never hidden. | A `COMPLETED` check with an incompleteness code, or a `PARTIAL` one without. The constructor raises in both cases. |
| C3 | Identical observations yield identical finding IDs and analysis digest. Per-run attribution (PIDs, times) is excluded from identity. | Two scans of an unchanged system with differing IDs or digest. |
| C4 | Process attribution is captured at observation time through a pinned `/proc` descriptor. A reused PID cannot be confused with the observed process. | A finding whose attribution belongs to a different process. |
| C5 | Shell analysis never guesses: syntax it cannot resolve is reported as a limitation, not as clean and not as a finding. | Unsupported syntax that produces neither a limitation nor a correct result. |
| C6 | A report verifies only if its hash manifest **and** a recomputation of its verdict, counts, coverage and baseline agree. | An edited report with recomputed hashes that still verifies. |
| C7 | Two builds of one source snapshot are byte-identical, on the same platform. | Differing bytes from `tools/build_full.py` run twice. |
| C8 | Every rule detects the artifact shape it targets and stays silent on that shape's benign twin, on a hermetic fixture host whose unplanted state reaches `NO_COMPROMISE_INDICATORS_OBSERVED`. | A planted scenario in `tools/validity.py` that is missed, a benign twin that alarms, or a rule with no positive scenario (`docs/DETECTION_VALIDITY.json`). This is recall on synthetic shapes, not sensitivity to real malware. |
| C9 | Every runtime line changed by a pull request arrives with tests that fail when the line is wrong: no mutant on a changed line survives (`tools/mutate.py --diff`). | A surviving or untested mutant on a changed line (CI job `mutation-diff`). The weekly whole-package table (`docs/MUTATION.md`) is the open work list, not a claim. |

## Method

**Collection.** Read-only access uses:

- no-follow directory descriptors and bounded reads;
- a fixed command allowlist (`ss`, `journalctl`, `dpkg --verify`, `rpm -Va`, `aa-status`, …);
- no shell and a minimal environment;
- per-command deadlines clamped to a whole-scan budget;
- probes in their own process group, killed afterwards.

**Coverage.** Each collector reports `reason_codes`: incompleteness of its own
target, for example `TIMEOUT`, `INPUT_TRUNCATED` or `PARSE_UNSUPPORTED`. It
separately reports `scope_limits`: what the chosen scope cannot see by design,
for example `OTHER_ACCOUNTS_NOT_VISIBLE` or `REQUIRES_SYSTEM_SCOPE`. Both come
from a closed vocabulary (`docs/DETECTORS.md`).

**Attribution.**

- *Processes:* PID, PPID, UID, kernel start time, boot ID, executable identity
  and hash, and the parent.
- *Browser extensions:* ID, name, version, enabled state, granted and declared
  permissions, install source, signature, linked native hosts.
- *Packages:* the package database present decides the method — `dpkg --verify`
  and `rpm -Va` through the allowlisted executor; pacman (mtree sha256) and apk
  (sha1) by comparing recorded digests with the files on disk, within fixed
  bounds. Results fall into five classes: changed content, changed
  configuration, missing file, metadata only, unverifiable. Repository trust
  settings are read for apt, dnf/yum, pacman and apk.

**Static shell analysis.** A quote-aware lexer recognises:

- literal execution from volatile paths;
- downloads or decoded data piped into interpreters;
- process substitution;
- command-valued settings (`PROMPT_COMMAND`, `alias`, `trap`).

It follows sourced files. A root-owned file whose content matches its dpkg
record is marked *package-attested*: a stated trust assumption.

**Verdict.** The outcome is one of:

- `SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION` (medium/high indicator present);
- `INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS` (an essential check is incomplete);
- `NO_COMPROMISE_INDICATORS_OBSERVED` (neither of the above).

None of them means "confirmed compromise" or "clean".

## Output

- Terminal: phases and a 10 s heartbeat on stderr; a Ukrainian interpretation on stdout.
- Private report in `~/falsicore-runs/run-*` (`0700`):
  - `dashboard.html` (offline, no JavaScript, strict CSP);
  - `report.md`;
  - JSON;
  - hash manifest.
- `explain --share-safe RUN` prints the same reading without paths, extension
  IDs or PIDs.

| Class | Meaning |
|---|---|
| `INDICATOR` | Observation requiring corroboration. Not a confirmed breach. |
| `EXPOSURE` | Capability or surface (broad permission, listener). Not intent. |
| `HARDENING` | Configuration that weakens defence. |
| `CONTEXT` | Usually benign fact. |

## Usage

Requires Linux and Python ≥ 3.10, standard library only.

| Task | Command |
|---|---|
| Scan, current user | `bash run.sh` (`--profile quick` / `deep`) |
| Scan, whole system (explicit) | `sudo /usr/bin/python3 -I "$PWD/falsicore.pyz" scan --scope system --target-user "$USER" --profile deep` |
| Scan an offline image (mounted, read-only) | `python3 -I falsicore.pyz scan --root /mnt/image --target-user alice --profile deep` — live-only checks are declared `SKIPPED`, never inferred; users come from the image's `/etc/passwd` |
| Re-read a report | `python3 -I falsicore.pyz explain RUN` |
| Verify a report | `python3 -I falsicore.pyz verify RUN` |
| Verify the application | `python3 -I falsicore.pyz verify-app && python3 -I falsicore.pyz self-test` |

From a source checkout, use `./run.sh [--profile …]` to scan and `python3 -I falsicore.py <command>` for everything else.
Ctrl-C stops the scan, kills the probes it started and exits with 130.

## Reproducing the evidence

```bash
sha256sum -c SOURCE_MANIFEST.sha256 && python3 tools/build_release.py --check-manifest
python3 -m unittest discover -s tests -q                     # full suite
python3 -m coverage run --branch --source=falsicore -m unittest discover -s tests -q
python3 tools/build_full.py /tmp/a && python3 tools/build_full.py /tmp/b && cmp /tmp/a/*.zip /tmp/b/*.zip
```

CI ([`verify.yml`](.github/workflows/verify.yml)) does the following:

- runs the suite on Python 3.10–3.14;
- runs ruff (correctness rules), bandit, CodeQL and a branch-coverage gate;
- compares double builds;
- repeats weekly, unattended.

Defects found, fault-injection results and gates are recorded in
[`docs/AUDIT.md`](docs/AUDIT.md). Measured values and their environment are in
[`docs/RELEASE_EVIDENCE.json`](docs/RELEASE_EVIDENCE.json).

## Grounding

Each design decision is traced to a verified primary source in
[`docs/BIBLIOGRAPHY.md`](docs/BIBLIOGRAPHY.md): the bounded verdict to the
base-rate fallacy and the critiques of detector evaluation (Axelsson 2000;
McHugh 2000; Sommer & Paxson 2010; Rossow et al. 2012); the trust boundary
to Thompson 1984 and Saltzer & Schroeder 1975; cross-view consistency to
Wang et al. 2005; integrity by recorded digest and its limit to Kim &
Spafford 1994; offline analysis to NIST SP 800-86; mutation and property
testing to DeMillo et al. 1978, Jia & Harman 2011, Just et al. 2014,
Inozemtseva & Holmes 2014 and Claessen & Hughes 2000. A source grounds a
decision; it does not certify the tool.

## Limitations

- **Detection.** Heuristic detectors, never validated against a malware
  corpus. Coverage percentages measure exercised code, not sensitivity.
- **Trust.** A live scan trusts the running kernel. A root, kernel or firmware
  adversary can forge every observation, including dpkg records.
- **Remote state.** Account sessions on remote services and deleted history
  are out of reach.
- **Deadline.** Probes are hard-bounded. A collector stuck in a blocking
  call is interrupted by a `SIGALRM` deadline (budget + 5 % grace, ≥2 s) and
  reported as `FAILED/BUDGET_EXHAUSTED` with its observations discarded; this
  works only when the scan runs in the main thread, which the CLI guarantees.

## License

[Apache-2.0](LICENSE).
