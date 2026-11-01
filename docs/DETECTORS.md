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
| `INSECURE_PACKAGE_SOURCE_SETTING` | package source disables signature or transport trust (apt `trusted=yes`/`Allow-Insecure`, dnf `gpgcheck=0`/`sslverify=0`, pacman `SigLevel Never`/`TrustAll`, apk `--allow-untrusted`); evidence names the manager and the codes | exceptional test repository |
| `PACKAGE_FILE_DRIFT` | non-configuration package file differs from the package database record (deep; dpkg `--verify`, rpm `-Va`, pacman mtree sha256, apk sha1) | local patch, interrupted upgrade, prelink |
| `PACKAGE_CONFFILE_CHANGED` / `PACKAGE_FILES_MISSING` | edited conffiles / recorded files absent (deep, context) | admin configuration / leftover modules of removed kernels |
| `PACKAGE_METADATA_DRIFT` | mode, owner, size or link target of a packaged file differs while content matches (deep, context) | administrator hardening; a new setuid bit is the case to review |
| `HIDDEN_PROCESS` | the kernel confirms a PID (`kill(pid, 0)`) that `/proc` does not list (readdir hook) or does not even resolve (lookup hook); threads and races are excluded by a confirming pass | almost none |
| `HIDDEN_KERNEL_MODULE` | a module `live` in `/sys/module` is absent from `/proc/modules` | none (built-ins have no `initstate` and are not counted) |
| `HIDDEN_LISTENER` | a listening socket is in `/proc/net` but not in the netlink table (`ss`), or the reverse; two `/proc/net` snapshots around the `ss` call exclude open/close races | none |
| `PROC_PID_MOUNT_OVERLAY` | a mount point over `/proc/<pid>` hides that process from every procfs reader | container runtimes mount inside `/proc`, not over process entries |

**Coverage:** quick profile intentionally omits authentication, package and kernel history. Standard/deep are snapshots rather than continuous EDR. Remote account sessions, encrypted communication contents, advanced rootkits and full disk provenance are out of scope.

**Python AST source audit:** nine rules `FC-AST-001`..`FC-AST-009` detect syntax patterns associated with CWE-94, CWE-78, CWE-502, CWE-377, CWE-295, CWE-400, CWE-703 and CWE-732. Static matching has false positives and negatives: aliases are only partly resolved, dangerous dataflow may not be obvious from a syntax tree, and false positives can be legitimate intentional code. These patterns do not imply CVE existence or exploitability. See `tools/code_audit.py` and `tools/evaluate_rules.py`.

## Cross-view consistency (`crossview`, 0.2.0)

The same fact read through two kernel interfaces must agree; a rootkit that
hooks one of them leaves a difference that needs no signature (cross-view
diff, Wang et al., DSN 2005). Four pairs are compared: the PID sweep
(`kill(pid, 0)` for every PID up to `kernel.pid_max`) against the `/proc`
listing and its `task/` thread IDs; `/sys/module/*/initstate == live`
against `/proc/modules`; `/proc/net/{tcp,udp}{,6}` listeners against the
netlink socket table (`ss`); and `/proc/self/mountinfo` for mounts over
`/proc/<pid>`. A candidate hidden process is confirmed only after a second
listing and probe (`PID_RECHECK_DELAY`), and a thread born in between is
recognised by its `Tgid`. Bounds: `PID_SWEEP_MAX`, the scan budget
(`BUDGET_EXHAUSTED` makes the check `PARTIAL`). Not claimed: a rootkit that
hooks both views of a pair, or that hides from the kernel itself, is unseen;
`crossview` is an essential check for the verdict like the other six.

`auth` without journald: when `journalctl` is absent, `/var/log/auth.log`,
`/var/log/secure` and `/var/log/messages` are read whole (8 MiB bound). Classic
syslog lines carry no year, so neither the 30-day window nor the incident
correlation is computed; the stats say `source: syslog_files`.

## Coverage reason codes (0.1.3)

`coverage_matrix.json` gives every check a `status`, plus `reason_codes`
(incompleteness of the check's own target) and `scope_limits` (what the
chosen scope or profile cannot see by design). `PARTIAL` requires at least one
reason code; `COMPLETED` cannot carry one.

| Incompleteness | Scope limit |
|---|---|
| `PERMISSION_DENIED`, `TOOL_MISSING`, `TOOL_FAILED`, `TIMEOUT`, `INPUT_TRUNCATED`, `ENUMERATION_LIMIT`, `BUDGET_EXHAUSTED`, `PARSE_UNSUPPORTED`, `MALFORMED_INPUT`, `HISTORY_UNAVAILABLE`, `SYMLINK_NOT_FOLLOWED`, `ATTRIBUTION_UNAVAILABLE`, `READ_FAILED` | `OTHER_ACCOUNTS_NOT_VISIBLE`, `REQUIRES_SYSTEM_SCOPE`, `NOT_IN_PROFILE`, `SOURCE_VANISHED`, `PACKAGE_ATTESTED_NOT_PARSED`, `LIVE_ONLY_NOT_IN_OFFLINE_IMAGE` |

## Offline image mode (`--root`, 0.2.0)

`scan --root /mnt/image --target-user NAME` reads a mounted root instead of
the live host (NIST SP 800-86: analysis of acquired media does not trust the
subject's running kernel). Users and homes come from the image's `/etc/passwd`;
`processes`, `network`, `kernel` and `crossview` are `SKIPPED` with
`LIVE_ONLY_NOT_IN_OFFLINE_IMAGE` and leave the essential set, so the verdict
speaks about the disk; every probe except `journalctl --directory=<root>/var/log/journal`
is refused (`SKIPPED`, scope limit, never "tool missing"); the user crontab is
the spool file (`/var/spool/cron/crontabs/NAME`, `/var/spool/cron/NAME`);
`dpkg` integrity compares the image's `*.md5sums` records with its files
within the same bounds as pacman/apk, and `rpm` is a declared limit (binary
database). `summary.mode` is `offline` and part of the report identity, so an
offline report is never compared with a live baseline.

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

## Shell analyser vocabularies (0.2.0)

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

## Package databases beyond dpkg (`falsicore/packages.py`, 0.2.0)

Pure, total, bounded helpers the collector wires in; none runs a package
manager, follows a symlink, or touches the network (`tests/test_packages.py`,
property-tested on arbitrary bytes/text):

- `detect_managers(root)` — which databases exist, by file presence only
  (`dpkg`: `var/lib/dpkg/status`; `rpm`: a `Packages`, `Packages.db` or
  `rpmdb.sqlite` inside `var/lib/rpm/` or `usr/lib/sysimage/rpm/`; `pacman`:
  `var/lib/pacman/local/`; `apk`: `lib/apk/db/installed`). A symlinked
  component makes a marker absent; `[]` means no marker, not "nothing
  installed".
- `parse_pacman_mtree(raw)` — libarchive mtree (`/set`, `/unset`, vis(3)
  escapes, `type=dir|link` recorded with their type) → `{path: {type, mode,
  uid, gid, size, md5, sha256, link}}` plus `{lines, malformed, truncated}`;
  200 000-line bound; a line with one malformed keyword is dropped whole.
- `parse_apk_installed(raw)` — apk-tools 2.x text index → packages and
  `{path: {package, sha1_b64, uid, gid, mode}}`; apk hashes a symlink's
  target string, not a file; apk-tools 3 ADB databases are not parsed.
- `rpm_verify_review(output)` — `rpm -Va` lines, same shape as
  `dpkg_verify_review` plus `metadata_changed_only` and
  `dependency_problems`; every non-blank line lands in exactly one counter.
- `detect_insecure_repo_settings(name, content)` — closed code set
  (`APT_TRUSTED_YES`, `APT_ALLOW_*`, `DNF_*_OFF`, `PACMAN_SIGLEVEL_NEVER`,
  `PACMAN_TRUSTALL`, `PACMAN_SIGLEVEL_OPTIONAL`, `APK_ALLOW_UNTRUSTED`);
  comments are inert; a setting the manager would reject may still be listed.

The collector wires these in (0.2.0): `detect_managers` decides which
databases exist; repository configuration of every manager present is read
(`/etc/apt/*`, `/etc/yum.repos.d/*.repo`, `/etc/dnf/dnf.conf`,
`/etc/pacman.conf`, `/etc/pacman.d/*.conf`, `/etc/apk/repositories`); in the
deep profile dpkg and rpm are verified through their own allowlisted
read-only commands (`dpkg --verify`, `rpm -Va`) while pacman and apk, which
have no such command, are verified by comparing recorded digests with the
files on disk inside fixed bounds (`VERIFY_PREFIXES`: executables, systemd
units, `/etc`; 20 000 files; 512 MiB; 8 MiB per file; the scan budget).
Package attestation of start-up files (`PACKAGE_ATTESTED_NOT_PARSED`) uses the
same records: dpkg md5, pacman sha256/md5, apk sha1/sha256; rpm hosts never
attest, because rpm's database is binary and is not parsed.

**What a package-database digest proves.** Equality of a file with its
recorded md5 (dpkg, pacman), sha1 (apk) or sha256 (pacman, rpm) is a
consistency check between two root-owned artefacts on the same disk. An
adversary with root rewrites the file *and* its record so they agree; md5 and
sha1 are not collision resistant. A match therefore means "unchanged since
recorded unless deliberately forged"; a mismatch means "differs from the
record" and says nothing about who changed it or why (local patch, prelink,
interrupted upgrade, administrator edit). Signed package files from an
independent mirror are the only stronger reference and are out of scope.
