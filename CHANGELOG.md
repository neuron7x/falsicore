# Changelog

## 0.2.0 — 2026-11-01

Universal, measured, refutable. Every item below is bound to a test, a
harness table or an audit row (`docs/AUDIT.md`, `docs/DETECTION_VALIDITY.json`,
`docs/MUTATION.md`).

- **Detection validity (claim C8).** `tools/validity.py` plants one artifact
  shape per scenario on a hermetic fixture host and requires the rule to fire
  and its benign twin to stay silent; 96 scenarios, 3 clean hosts (user,
  system, offline) at `NO_COMPROMISE_INDICATORS_OBSERVED`; the table is
  committed and CI fails when it is stale. Recall on synthetic shapes, not
  sensitivity to malware.
- **Property-based testing.** Universally quantified claims for the shell
  analyser, finding identity, digests, adapters and bounded reads
  (Hypothesis, CI only). Stating them refuted seven behaviours (P-1…P-9);
  all fixed, counterexamples kept as plain tests.
- **Mutation testing (claim C9).** `tools/mutate.py` (stdlib) with per-test
  selection from coverage contexts; CI gate on changed lines; weekly
  whole-package table. External 0.1.3 baseline 56 % killed recorded;
  `detectors.py` now 0 open items.
- **Cross-view consistency** (`crossview`, essential): hidden processes
  (PID sweep vs `/proc`, confirming pass, `Tgid`), hidden modules (sysfs vs
  `/proc/modules`), hidden listeners (`/proc/net` vs netlink, two snapshots),
  mounts over `/proc/<pid>`.
- **Universal package managers.** dpkg, rpm (`rpm -Va`), pacman (mtree
  sha256) and apk (sha1) integrity within fixed bounds; repository trust
  settings for apt, dnf/yum, pacman, apk; rules renamed `PACKAGE_*`,
  `INSECURE_PACKAGE_SOURCE_SETTING`; new `PACKAGE_METADATA_DRIFT`.
- **Offline image mode** (`scan --root`): live-only checks declared, never
  inferred; users from the image's `/etc/passwd`; crontab spool; image
  journal via `journalctl --directory`; `summary.mode` in the report identity.
- **auth without journald:** `/var/log/auth.log`, `secure`, `messages`.
- **Hard whole-scan deadline (A-8 fixed):** `SIGALRM` after budget + grace
  interrupts a blocked collector; probe cleanup runs with the alarm deferred.
- **Shell analyser:** code from substitutions (`eval "$(curl …)"`, `sh -c "$(…)"`)
  attributed to its source; `/dev/tcp` reverse shells (`NETWORK_REDIRECTION`);
  NUL bytes cannot forge markers; `/tmp/done` no longer escapes as a keyword.
- **No site special-cased:** extension assessment reports `host_scope` and
  `content_script_scope` from the match-pattern grammar.
- **Injectable scan root** for all system paths; `mypy` zero-error gate;
  typed profiles; local `tools/gate.py` mirroring CI; verified bibliography
  (`docs/BIBLIOGRAPHY.md`).
- Report schema `falsicore.summary.v5`; v4 reports read as LEGACY.

## 0.1.3 — 2026-10-28

Repair release driven by three separate review passes; register and evidence
in `docs/AUDIT.md`.

- **Coverage semantics.** Closed reason-code vocabulary. `PARTIAL` requires an
  incompleteness reason; scope limits (other accounts, system scope, profile
  depth, package-attested syntax) are reported separately and no longer make
  every scan inconclusive.
- **Attribution at observation time.** Process findings record PID, PPID,
  UID, kernel start time, boot ID, executable metadata and hash, and the
  parent, read through a pinned `/proc` dirfd. Finding IDs no longer depend on
  PIDs.
- **Browser findings explained automatically.** Extension name, ID and
  version; enabled state and granted permissions from browser preferences;
  install location and signature; content-script matches; linked native
  hosts. Custom-named Chromium profiles are inspected. A DevTools pipe is no
  longer described as a network port; a debug port is correlated with
  observed listeners.
- **Shell analysis.** A quote-aware lexer replaces line joining before
  `shlex`. It closes false negatives (functions, wrappers, `alias`,
  `PROMPT_COMMAND`, `trap`, redirections, process substitution, stdin
  interpreters) and a comment/backslash evasion; data in multi-line strings
  is no longer classified as commands. Files sourced from start-up files are
  followed. Root-owned files matching their dpkg record are labelled
  package-attested.
- **Executor.** stderr is separated from parsed output. Leaders are never
  reaped before the final group kill; residual group members are killed and
  reported; signal deaths are labelled.
- **Operator experience.** Progress and heartbeat on stderr; Ukrainian
  interpretation of every finding in the terminal, Markdown and HTML;
  `explain --share-safe`; Ctrl-C returns 130 and names the incomplete run; an
  incompatible `--compare` is refused before collection; 0.1.2 reports are
  read as `LEGACY`.
- **Release.** One deterministic full ZIP (`tools/build_full.py`) with its hash
  outside the archive; builds never edit the tree; constant archive prefix;
  CodeQL pinned to a commit; CI adds ruff, bandit and a coverage gate (88%).
- **Tests.** 431 → 548. Four lifecycle tests that failed (and one that passed
  vacuously) on hosts with non-ASCII `.pth` files now isolate their child
  interpreters. No previous test file was removed.
- `dpkg --verify` output is classified (content change vs conffile vs missing vs
  unverifiable); previously all lines counted as drift. Launcher options such as
  `bash run.sh --profile deep` imply a default scan.
- CI workflows are outside the source manifest (shipped and checksummed in the
  full ZIP), so automated workflow updates no longer break verification;
  weekly scheduled CI.
- Report schema `falsicore.summary.v4`.

## 0.1.2 — 2026-10-27

- Restored the final 0.1.0 subprocess, collector, report and packaging safeguards
  and three regression-test files missing from the 0.1.1 distribution.
- Replaced cross-file shell co-occurrence matching with bounded lexical command
  context analysis, explicit script operands and connected-pipeline checks.
- Added command locations and static-analysis limitations without exporting
  shell contents. Literal cache paths and printed examples are not execution.
- Corrected plain base64 decoding: data decoding alone is not an execution
  context. Changed two legacy fixtures accordingly and added execution cases.
- Added cron schedule and desktop Exec adapters so stricter command matching
  does not silently discard scheduled or autostart commands.
- Reused bounded process-group cleanup for portable self-tests. Keyboard
  interruption now terminates owned probe subprocess groups before propagation.
- Added a single-file, reproducible .pyz distribution with integrity preflight,
  explicit self-test and no-overwrite source export. No persistent extraction.
- Separated collector errors from visibility limitations in terminal output;
  added offline evidence details in the HTML report.
- No automatic changes to host configuration, packages, credentials or reports.

## Historical releases

0.1.0 and 0.1.1 are superseded. Their old verification claims are not evidence
for 0.1.2; only the current recorded commands and results support this release.
