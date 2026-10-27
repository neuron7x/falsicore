# Changelog

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
