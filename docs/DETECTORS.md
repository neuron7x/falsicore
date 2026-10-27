# Detector catalog and evidence semantics

The endpoint scanner uses **context-sensitive heuristics**, not signatures for known malware. Categories:

- `INDICATOR`: potentially suspicious observation. Medium/high indicators require investigation; none proves compromise.
- `EXPOSURE`: browser permissions, policies or externally bound services requiring authorization review.
- `HARDENING`: configuration choices affecting defense, not evidence of an intruder.
- `CONTEXT`: facts such as an SSH login or file drift, often fully legitimate.

Examples of detector IDs:

| Rule ID | Observation | Typical benign alternative |
|---|---|---|
| `EXECUTABLE_IN_VOLATILE_PATH` | process executable under `/tmp`, `/var/tmp`, `/dev/shm` | test/development binary |
| `DELETED_RUNNING_EXECUTABLE` | executable path marked deleted | package update |
| `TEMP_PROCESS_PUBLIC_EGRESS` | observable public network connection linked to volatile process | development service |
| `SUSPICIOUS_SYSTEMD_EXECUTION` | risky unit execution pattern | maintenance automation |
| `SUSPICIOUS_CRON_EXECUTION` | cron contains risky execution syntax | authorized scheduled job |
| `SYSTEM_LOADER_PRELOAD` | system dynamic-loader preload configured | instrumentation/compatibility |
| `POWERFUL_BROWSER_EXTENSION` | powerful browser extension API/host access | legitimate extension with broad permissions |
| `REMOTE_ACCESS_PORT_EXPOSED` | remote-access listener on a non-loopback bind | intentionally enabled SSH/RDP/VNC |
| `INSECURE_APT_REPOSITORY_SETTING` | APT source override of signature trust | exceptional test repository |

**Coverage:** quick profile intentionally omits authentication, package and kernel history. Standard/deep are snapshots rather than continuous EDR. Remote account sessions, encrypted communication contents, advanced rootkits and full disk provenance are out of scope.

**Python AST source audit:** nine rules `FC-AST-001`..`FC-AST-009` detect syntax patterns associated with CWE-94, CWE-78, CWE-502, CWE-377, CWE-295, CWE-400, CWE-703 and CWE-732. Static matching has false positives and negatives: aliases are only partly resolved, dangerous dataflow may not be obvious from a syntax tree, and false positives can be legitimate intentional code. These patterns do not imply CVE existence or exploitability. See `tools/code_audit.py` and `tools/evaluate_rules.py`.
