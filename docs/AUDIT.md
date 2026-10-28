# FALSICORE 0.1.3 — audit record

This record covers the 0.1.2 → 0.1.3 repair. Three read-only review passes ran
as separate agents. Each had its own scope: A, execution and subprocess
lifecycle; B, collection, parsing and attribution; C, verdicts, privacy,
reporting and packaging. Every review drew on the same model family, so this is
**not** an independent third-party assessment. One integrator made every change.

Baseline: 0.1.2 source (commit `b0d80e8`) on Ubuntu 24.04.4, Python 3.12.3,
UID 1000. On that host the suite ran 431 tests: 427 passed and 4 failed. The
4 failures are D1 below. The release claim of "431/431" had been measured on
Debian 13 / Python 3.13.5 and did not reproduce on this host.

## Defect register

Status `FIXED` means a regression test exists, it fails when the fix is
removed (see *Fault injection*), and the full suite passes. Line references
point to 0.1.3 code.

| ID | Where | Violated invariant / impact | Fix | Test |
|---|---|---|---|---|
| D1 | tests (`test_final_hardening`, `test_v32_assurance`, `test_interrupt_cleanup`) | Child interpreters were started without `-I`. On a host with non-ASCII `.pth` files, the 4 lifecycle tests failed. Worse, the "grandchild holds the pipe" test passed **vacuously**, because the grandchild crashed at start-up. | `-I` for every disposable child interpreter | the same tests; mutant D1 |
| A-1 | `monitor.py` | `systemctl --user` ran in the minimal probe environment, so enable/status could never reach the user bus. `enable` wrote unit files before it failed. | `user_bus_env()`: XDG runtime directory only if private to this UID; preflight before writing | `test_monitor_env.py` |
| A-2 | `cli.py`, `bundle.py` | No progress for up to 97 s (scan) or 180 s (self-test). | `Progress` on stderr: phase, `[i/N]`, 10 s heartbeat. Self-test heartbeat and failure reason. | `test_progress.py` |
| A-3, B-10 | `cli.py` `Progress`, `collectors.py` `scan` | A closed stderr redirected progress to stdout, or a broken pipe aborted the whole scan. | `stream=None` turns progress off; an OSError disables it; the collector isolates callback errors | `ProgressFailureIsolationTests` |
| A-4 | `cli.py` scan | Ctrl-C ended in a raw traceback and left an unexplained empty run folder. | `SCAN CANCELLED`, run path printed, exit 130; owned probe groups are killed | `test_keyboard_interrupt_returns_130_with_run_path`; live SIGINT run (below) |
| A-5, A-6 | `safety.py` `_run_bounded` | A daemonised grandchild survived a `COMPLETED` probe. The leader was reaped before `killpg`, so its PID or group could be reused. | The leader is observed with `waitid(WNOWAIT)` and never reaped before the final `killpg`; residual members are reported | `test_executor_lifecycle.py` |
| A-7 | `safety.py` | A death by signal could not be told apart from exit 1. An escaped pipe holder went unlabelled. | `error="signal:SIGSEGV"`; `PIPE_HOLDER_OUTSIDE_GROUP` | same |
| A-8 | `collectors.py` `scan` | The whole-scan deadline is cooperative. A blocking read inside a collector is not interrupted. | **Not fixed.** Per-command deadlines are clamped to the remaining budget, and an overrun turns into `PARTIAL/BUDGET_EXHAUSTED`. A hard watchdog would need collectors in child processes. | documented limitation |
| A-9 | `safety.py` | stderr was merged into the parsed stdout: journalctl hints were miscounted as malformed, bus errors were shown as a status. | Separate bounded stderr (64 KiB), never parsed as data | `test_stderr_is_separate_from_parsed_stdout` |
| B-1 | `collectors.py` `processes` | Exposure records kept only the PID, so after the process exited (an observed browser process in the originating incident) it could not be identified. | A pinned `/proc/<pid>` dirfd. Observations capture PID, PPID, UID, `start_ticks` (stat field 22), `boot_id`, executable name, dev:ino, mode, owner, bounded SHA-256, and the parent's start time and name. | `LiveProcessAttribution` (disposable `/tmp` copy of `sleep`) |
| B-2 | `processes` | A cmdline longer than 8 KiB lost its flags with no record, and the scan reported clean. | 64 KiB bound; overflow counts as `INPUT_TRUNCATED` → PARTIAL | `test_truncated_cmdline_is_incompleteness_not_clean` |
| B-3 | `detectors.browser_flag_review` | `--remote-debugging-pipe` was merged with network weakening. | Sandbox, trust, pipe and port are now separate. A port is checked against observed listeners (`LISTENING_LOOPBACK_ONLY`, `…_BEYOND_LOOPBACK`, `NOT_OBSERVED`, `UNKNOWN`). | `BrowserFlagSemantics` |
| B-4 | `_scan_chromium`, `_scan_firefox` | Extensions appeared only as an opaque hash, so the operator had to dig by hand. Disabled Chromium extensions were reported as active. | Identity block: ID, resolved name, version, profile ref, enabled (or `UNKNOWN`), granted vs declared permissions, content-script matches, install location, Web Store / signature state, linked native hosts | `ChromiumIdentity`, `FirefoxAndNativeHosts` |
| B-5 | `_native_hosts` | The evidence was only a hash. The home-prefix test also matched `/home/userx`. | Host name, allowed extensions, manifest owner, executable metadata and hash; the prefix ends in `/` | `test_native_host_links_and_home_prefix_boundary` |
| B-6 | `shell_syntax.py` | False negatives were reported with no limitation, i.e. as clean: functions, braces, `timeout`/`nice`/`xargs`, `alias`, `PROMPT_COMMAND`, `trap`, `< file`, `2>` operands, `<(curl)`, `curl \| python3`, `perl`/`node` scripts. | A quote-aware lexer with comment, substitution, redirection and here-doc handling; a wrapper set; command-valued settings; stdin interpreters | `test_shell_adversarial.py` (41 cases) |
| B-7 | `shell_syntax.py` | A trailing backslash inside a comment, or `\\`, joined the next line, which then disappeared into the comment. This is an evasion. | Continuation is decided by the lexer, not by text before lexing | `comment_*_does_not_continue` |
| B-8 | `shell_syntax.py` | Data inside a multi-line string was classified as a command. | Multi-line quoting is lexed as one word | `multiline_*_data` |
| B-9, C-2 | `collectors.py` `checked` | Coverage gave only a status and free text. | A closed vocabulary: `reason_codes` (incompleteness) and `scope_limits`. `PARTIAL` requires a reason; `COMPLETED` forbids one. | `CoverageVocabulary` |
| C-1 | verdict | `NO_COMPROMISE_INDICATORS_OBSERVED` could never be reached: inherent scope limits counted as incompleteness. | Scope limits (other accounts, system scope, profile depth, package-attested syntax) are reported but do not make a defined target incomplete | `test_verdict_reachable_when_only_scope_limits_remain` |
| B-11 | `_scan_chromium` | Only `Default` and `Profile N` were inspected. Custom-named profiles, which this host has, were never looked at. | Any profile folder with `Preferences` or `Extensions` | `test_custom_named_profile_and_full_identity` |
| B-12 | `persistence` | `/usr/lib/systemd/user` was not an inspected root, so links into it went unseen (42 gaps on this host). | Vendor user units added; symlinks are covered when their target lies inside an inspected root | `test_vendor_user_units_are_inspected_roots` |
| B-13 | `persistence` | Cron and autostart parse limits were discarded. Files sourced from `.bashrc` were never analysed. | Limits are surfaced. Sourced files are followed (home and non-attested; max 24). Root-owned files identical to their dpkg record count as `PACKAGE_ATTESTED_NOT_PARSED` (a stated trust assumption). | `ShellFollowAndAttestation`, `PersistenceFixtures` |
| C-3, C-4 | `report.py`, `cli.py`, `guide.py` | No Ukrainian per-finding explanation; the terminal did not show exposures at all. | `guide.RULES` gives each rule an observation, benign alternatives, uncertainty, P1–P3 and a non-destructive step. The terminal shows them all. | `GuideCompleteness`, CLI tests |
| C-5 | `report.py` | An edited baseline with recomputed hashes verified as genuine, and the comparison was labelled "VERIFIED". | The baseline is bound into the analysis digest; the status is renamed `LOCAL_CONSISTENT_COMPARISON` | `test_baseline_tamper_with_recomputed_manifest_is_rejected` |
| C-6 | `cli.py` | An incompatible `--compare` failed only after the full scan, with an English message that did not say why. | Preflight before collection that names the differing fields; auto-compare reports how many baselines it skipped and why | `test_incompatible_compare_is_refused_before_collection` |
| C-7 | `collectors.py`, `report.py` | PIDs were part of the finding hash, so IDs changed on every scan. | Per-run attribution moves to `observations`, which are excluded from IDs and the digest; the source is the executable path | `test_finding_id_is_independent_of_pid` (live), `test_identical_findings_merge…` |
| C-8 | `report.py`, `guide.py` | Markdown and terminal output passed HTML and C0/C1/bidi controls through. | `terminal_safe` plus entity escaping | `test_markdown_neutralises…`, explain test |
| C-9 | `report.py` | Markdown silently cut findings at 350. | An explicit "… ще N" marker | `test_markdown_marks_omitted_findings` |
| C-10 | `tools/build_release.py` | The ZIP prefix came from the checkout folder name. | `falsicore-<version>/` | `test_archive_bytes_do_not_depend_on_checkout_folder_name` |
| C-11 | workflows, `Makefile` | No full-ZIP build; builds rewrote `SOURCE_MANIFEST`; CodeQL was unpinned. | `tools/build_full.py` (one deterministic full ZIP, hash kept outside it); builds never edit the tree; `--check-manifest` in CI; CodeQL pinned to the commit of v4.39.1, resolved through the GitHub API | `test_full_distribution.py` |
| C-12 | docs | Stale claims (431/431, "one Python file", "select a license"). | Rewritten or removed (this release) | review |
| C-13 | — | No progress on stderr | see A-2 | — |
| R-1 | full ZIP / `START_HERE_UA.md` | Found by clean-extraction verification: Python's `zipfile` extractor does not restore the execute bit, so `./run.sh` is refused (`unzip` keeps it). | The operator command is `bash run.sh`, which works with any extractor | clean-extraction receipt |
| R-2 | tests (`test_failure_paths`, `test_review_regressions`) | Found by the packaged self-test: two new fixtures passed only while `TMPDIR` was outside `/tmp`. With fixtures under `/tmp` (self-test minimal env, CI) the temp-path rule masked the property under test. | Each test isolates its rule by patching the volatile-prefix table; the suite passes with `TMPDIR=/tmp`, with a home-based `TMPDIR`, and in a minimal environment | same tests |
| R-3 | tests (`test_assurance01`, `test_v3_engineering`) | Found by hosted CI (run 40597331933): four older monitor tests mocked `run_command` but not the new A-1 runtime-directory preflight. They passed only on hosts with a login session (`/run/user/<uid>`). | The preflight is patched in those test classes and covered on its own in `test_monitor_env.py`; reproduced locally with the runtime base pointed at a missing directory | same tests |
| R-4 | `tests/test_executor_lifecycle.py` | Found by hosted CI (run 40643424328, Python 3.12 job): the signal-label test used SIGSEGV. The runner's core-dump handler outlasted the 3 s deadline, so the probe was killed by the timeout (`-9`). The executor behaved correctly; the fixture was environment-dependent. | SIGTERM (no core dump) exercises the same contract | same test |
| R-5 | `tests/test_monitor_env.py` | CodeQL `py/overly-permissive-file` flagged the fixture modes `0o755` and `0o750`. | The fixture uses `0o701`, still refused because `mode & 0o077 ≠ 0` | same test |
| L-1 | `cli.py` explain/verify | A 0.1.2 (schema v3) report was rejected as "integrity failed". | Detected as `LEGACY`: file hashes are checked, semantics are not re-derived, and it is never compared with new reports | `LegacyReports` |

## Fault injection (targeted mutation)

The script `.falsicore-audit/mutation.py` (private, not shipped) copies the
tree, removes one protection, and runs the relevant test module. Result:
**25 of 25 mutants were killed** (`.falsicore-audit/mutation_results.json`).
This was targeted, not whole-project mutation testing. Two caveats:

- The A-4 mutant was killed because the runner aborted, not by an assertion.
- The D1 mutant is killed only on hosts with non-ASCII `.pth` files.

## Methodology mapping

These are adopted practices. No compliance or certification is claimed.

| Source | Concrete requirement adopted | Where tested |
|---|---|---|
| NIST SP 800-218 (SSDF) PW.7, PW.8 | Review code and test executable code before release; keep the results | review passes A/B/C; full suite; coverage; mutation |
| SSDF PS.2, PS.3 | Release integrity information; archive each release | `SOURCE_MANIFEST.sha256`, `SHA256SUMS`, external ZIP hash, two byte-identical builds |
| SSDF RV.1, RV.2 | Collect, analyse and fix vulnerabilities with regression tests | defect register above |
| Microsoft SDL: threat modelling, static analysis, dependency review | Threat model is updated; bandit and ruff checks; CodeQL pinned; no runtime dependencies | `docs/THREAT_MODEL.md`, `verify.yml` static-analysis job |
| Google review guide ("Looking for"): tests, naming, complexity, documentation | Every fix has a test; comments state invariants; no new abstraction without need | review |
| Claude Code permissions / sandboxing docs | The agent works as UID 1000 with no sudo; no privileged scan was performed | G1/G11 below |

## Gates

| Gate | Status | Evidence / limit |
|---|---|---|
| G1 host and user work preserved | PASS | Writes were limited to: the repository working copy; new private run folders (`~/falsicore-runs/run-*` and the agent scratch folder); `.falsicore-audit/`; disposable `/tmp/fc-attr-*` test copies, which are removed after each test. Nothing was deleted from `~/falsicore-runs`. There was no browser, shell, service, package or extension change. |
| G2 release-blocking defects fixed | PASS | B-1, B-4, B-6 and every major finding above. A-8 stays a documented limitation. |
| G3 complete retained suite passes | PASS | 544 discovered / 544 passed / 0 failed / 0 errors / 0 skipped. All 24 baseline test files are kept; 31 now. |
| G4 positive/negative/failure tests for changed logic | PASS | per-row tests; `test_failure_paths.py` |
| G5 progress, cancellation, deadlines via real launcher | PASS | `./run.sh` progress and heartbeat. Live SIGINT during `dpkg --verify` (a deep profile run under this account): the scan exited 40 ms later, the owned `dpkg` child was killed, exit 130. |
| G6 attribution retained | PASS | Live test with a disposable process. A historical PID from a 0.1.2 run **cannot** be reconstructed: 0.1.2 did not record it. |
| G7 reports consistent, escaped, private | PASS | 0700/0600; CSP; escaping tests; baseline-tamper test |
| G8 reproducibility | PASS (same environment only) | Two pyz builds and two full ZIP builds are byte-identical on this host. No cross-platform claim. |
| G9 clean-extraction verification | see release receipt next to the ZIP | |
| G10 authorised local workflow exercised | PASS (user scope) | standard and deep user-scope runs |
| G11 unperformed checks identified | PASS | no system-scope run (no authorisation); hosted CI: the first run on the pushed commit failed (R-3) and is kept as a negative result; the run on the fix is recorded in the release receipt; coverage 89% < 100% target; no malware-corpus validation |

## Coverage

Branch-aware coverage of runtime package `falsicore/`, with no exclusions:

- statements: 3015, of which 2744 covered;
- branches: 1368, of which 1173 covered;
- overall: **89%**.

Weakest module: `guide.py` (67%, rendering branches for rare evidence shapes),
then `monitor.py` (81%) and `collectors.py` / `safety.py` (86%). Missing lines
are listed by `coverage report -m`, and the CI gate is 88% (previously 86%).
The 100% target was **not reached**. Coverage measures exercised code, not
detection accuracy.

## Limitations that remain

- Heuristic detectors; no validation against a real malware corpus.
- A live scan trusts the running kernel. A root or kernel adversary can forge
  every observation, the dpkg md5 records included.
- The shell lexer is a deliberate subset. Unresolved program identity is
  reported as `PARSE_UNSUPPORTED`, never guessed.
- User scope cannot see other accounts' processes or sockets, root-only files,
  or non-dumpable processes of its own account. These appear as scope limits.
- The global deadline is cooperative (A-8).
