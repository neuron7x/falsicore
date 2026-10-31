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
| `DPKG_FILE_DRIFT` | non-configuration package file differs from its dpkg md5 (deep) | local patch, interrupted upgrade |
| `DPKG_CONFFILE_CHANGED` / `DPKG_FILES_MISSING` | edited conffiles / recorded files absent (deep, context) | admin configuration / leftover modules of removed kernels |

**Coverage:** quick profile intentionally omits authentication, package and kernel history. Standard/deep are snapshots rather than continuous EDR. Remote account sessions, encrypted communication contents, advanced rootkits and full disk provenance are out of scope.

**Python AST source audit:** nine rules `FC-AST-001`..`FC-AST-009` detect syntax patterns associated with CWE-94, CWE-78, CWE-502, CWE-377, CWE-295, CWE-400, CWE-703 and CWE-732. Static matching has false positives and negatives: aliases are only partly resolved, dangerous dataflow may not be obvious from a syntax tree, and false positives can be legitimate intentional code. These patterns do not imply CVE existence or exploitability. See `tools/code_audit.py` and `tools/evaluate_rules.py`.

## Coverage reason codes (0.1.3)

`coverage_matrix.json` gives every check a `status`, plus `reason_codes`
(incompleteness of the check's own target) and `scope_limits` (what the
chosen scope or profile cannot see by design). `PARTIAL` requires at least one
reason code; `COMPLETED` cannot carry one.

| Incompleteness | Scope limit |
|---|---|
| `PERMISSION_DENIED`, `TOOL_MISSING`, `TOOL_FAILED`, `TIMEOUT`, `INPUT_TRUNCATED`, `ENUMERATION_LIMIT`, `BUDGET_EXHAUSTED`, `PARSE_UNSUPPORTED`, `MALFORMED_INPUT`, `HISTORY_UNAVAILABLE`, `SYMLINK_NOT_FOLLOWED`, `ATTRIBUTION_UNAVAILABLE`, `READ_FAILED` | `OTHER_ACCOUNTS_NOT_VISIBLE`, `REQUIRES_SYSTEM_SCOPE`, `NOT_IN_PROFILE`, `SOURCE_VANISHED`, `PACKAGE_ATTESTED_NOT_PARSED` |

Skipped checks use `PROFILE_EXCLUDED` or `BUDGET_EXHAUSTED`; failed collectors
use `COLLECTOR_ERROR`.

## Evidence fields (0.1.3)

- `evidence` is canonical: it determines the finding ID and the analysis
  digest.
- `observations` hold per-run attribution and are excluded from both. For
  processes they record `pid`, `ppid`, `uid`, `start_ticks`, `boot_id`,
  `exe_name`, `exe_ref` (private path index) and `executable` (dev:ino,
  owner, mode, mtime, bounded SHA-256), plus a `parent` block.
- Browser extension findings carry an `extension` block: ID, name (with its
  source), version, profile ref, `enabled`, `granted`, declared and optional
  permissions, content-script matches, install location, Web Store or
  signature state, and `native_hosts_allowing`. Any value not observable
  locally is `UNKNOWN`.
- `UNSAFE_BROWSER_LAUNCH_FLAG` separates `sandbox_reduced`, `debug_channel`
  (`pipe` or `port`), `debug_port` and `debug_port_listener`.

## Shell analyser vocabularies (0.1.4)

`shell_syntax.analyze` emits only codes from two closed sets (property-tested on
arbitrary input, `tests/test_properties.py`):

- patterns `PATTERN_CODES`: `TEMP_PATH_IN_EXECUTION`, `REMOTE_SCRIPT_PIPELINE`,
  `BASE64_DECODE_EXECUTION_CONTEXT`, `RISKY_EXECUTION_FLAG`, `NETWORK_REDIRECTION`
  (a redirection to `/dev/tcp/…` or `/dev/udp/…`: the shell itself opens a socket);
- limitations `LIMITATION_CODES`: `TOKEN_LIMIT`, `UNTERMINATED_HEREDOC`,
  `UNPARSED_QUOTING`, `EXPANSION_NOT_RESOLVED`, `INLINE_INTERPRETER_CODE_NOT_ANALYZED`,
  `MISSING_SHELL_COMMAND_OPERAND`, `HEREDOC_EXPANSION_NOT_RESOLVED`, `NESTING_LIMIT`,
  `INPUT_LIMIT`, `INCOMPLETE_CONTINUATION`, `NUL_IN_INPUT`.

Any limitation makes the owning check `PARTIAL` with `PARSE_UNSUPPORTED` (or
`PACKAGE_ATTESTED_NOT_PARSED` for a root-owned file equal to its dpkg record).
`NUL_IN_INPUT`: NUL bytes are removed at the public entry because NUL is the
analyser's private marker byte; input can therefore never forge a marker.

Code that reaches an interpreter through a substitution is attributed to the
substitution's source: `eval "$(curl …)"`, `sh -c "$(curl …)"`,
`python3 -c "$(curl …)"` and `PROMPT_COMMAND="$(curl …)"` are
`REMOTE_SCRIPT_PIPELINE`; `bash -c "$(… | base64 -d)"` is
`BASE64_DECODE_EXECUTION_CONTEXT`. The evaluated text itself stays
`EXPANSION_NOT_RESOLVED`. Known, documented gaps: a download bound to a
variable first (`x=$(curl …); eval "$x"`), a relative program after `cd`
(`cd /tmp && ./x`), and the output of a local program (`eval "$(dircolors …)"`)
are limitations only.

`falsicore/guide.py` holds the Ukrainian interpretation of every rule: the
observation, benign alternatives, uncertainty, priority P1–P3 and a
non-destructive step. A test enforces that every emitted rule has an entry.
