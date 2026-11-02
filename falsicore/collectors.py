"""Bounded passive collectors for Linux. No socket connections or command execution of artifacts."""
from __future__ import annotations

import base64
import copy
import datetime as dt
import gzip
import hashlib
import hmac
import ipaddress
import io
import json
import os
import pwd
import re
import signal
import stat
import threading
import time
from collections import Counter
from zlib import error as zlib_error
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, Callable, Iterable

from . import detectors as d
from . import packages as pk
from .shell_syntax import analyze as analyze_shell
from .config_commands import cron_commands, desktop_commands
from .safety import run_command, safe_read, utc_now
from .profiles import COLLECTOR_ORDER, config_for

def _extension_version_key(directory: Path) -> tuple[tuple[int, int | str], ...]:
    """Natural numeric version ordering; lexicographic 9 > 10 is incorrect."""
    return tuple((0, int(part)) if part.isdecimal() else (1, part.lower())
                 for part in re.split(r"[._-]", directory.name))



def _allowed_audit_invocation(name: str, args: list[str]) -> bool:
    """Permit only nonmutating, fixed-purpose forensic probes.

    The command runner is also used by the separately opted-in scheduler.
    Keeping this policy at the Audit boundary prevents a future collector
    from accidentally invoking a state-changing systemctl/dpkg variant.
    """
    exact = {
        "uname": ["-r"], "ss": ["-H", "-tuna", "-p"],
        "dpkg": ["--verify"], "rpm": ["-Va"], "aa-status": ["--enabled"],
        "mokutil": ["--sb-state"],
    }
    if name in exact:
        return args == exact[name]
    if name == "crontab":
        return args == ["-l"] or (len(args) == 3 and args[:2] == ["-l", "-u"]
                                       and bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args[2])))
    if name == "journalctl":
        # Fixed read-only query shapes: auth/authpriv facility, or kernel transport.
        # An offline image's own journal may be read through --directory=<root>/var/log/journal.
        if args and args[0].startswith("--directory="):
            directory = args[0][len("--directory="):]
            if not (directory.startswith("/") and directory.endswith("/var/log/journal") and ".." not in directory.split("/")):
                return False
            args = args[1:]
        matches = (["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], ["_TRANSPORT=kernel"])
        return (len(args) >= 8 and args[:-7] in matches and args[-7] == "--since"
                and bool(re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", args[-6]))
                and args[-5] == "--lines" and args[-4].isdigit() and len(args[-4]) <= 6
                and 0 <= int(args[-4]) <= 100000 and args[-3:] == [
                    "--no-pager", "--output=json",
                    "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"])
    return False

# Coverage vocabulary. A check is PARTIAL only when its defined target was not
# fully inspected (INCOMPLETE_CODES). Scope limits describe what the chosen
# scope/profile cannot see by design; they are reported, not hidden, but they
# do not turn an inspected target into an incomplete one.
INCOMPLETE_CODES = {
    "PERMISSION_DENIED": "an object inside the check's own target could not be read",
    "TOOL_MISSING": "a required read-only tool is not installed",
    "TOOL_FAILED": "a probe command exited unsuccessfully",
    "TIMEOUT": "a probe command hit its deadline",
    "INPUT_TRUNCATED": "an input exceeded its size bound and was cut",
    "ENUMERATION_LIMIT": "the item/visit cap for this profile was reached",
    "BUDGET_EXHAUSTED": "the whole-scan runtime budget ran out",
    "PARSE_UNSUPPORTED": "syntax outside the static analyser's supported subset",
    "MALFORMED_INPUT": "an input could not be parsed",
    "HISTORY_UNAVAILABLE": "the requested history window was not retained or not returned",
    "SYMLINK_NOT_FOLLOWED": "a symlink pointing outside the inspected roots was not followed",
    "ATTRIBUTION_UNAVAILABLE": "an observed object could not be attributed to a process",
    "READ_FAILED": "an unexpected read error occurred",
}
SCOPE_LIMIT_CODES = {
    "OTHER_ACCOUNTS_NOT_VISIBLE": "objects of other accounts are invisible in user scope",
    "REQUIRES_SYSTEM_SCOPE": "this part of the check runs only with --scope system",
    "NOT_IN_PROFILE": "this part of the check runs only in a deeper profile",
    "SOURCE_VANISHED": "the object disappeared between enumeration and reading",
    "PACKAGE_ATTESTED_NOT_PARSED": "root-owned file identical to its dpkg record; unsupported syntax not analysed, package trust assumed",
    "LIVE_ONLY_NOT_IN_OFFLINE_IMAGE": "this part reads the running kernel or runs a probe; an offline image has neither",
    "EVAL_OF_ATTESTED_PROGRAM_OUTPUT": "a start-up file executes the output of a package-attested program; that output "
                                       "is not analysed, the program's package is trusted (its inputs are not)",
}
# Programs whose output is their input: evaluating it is evaluating unknown data,
# so attestation of the program itself proves nothing about the code.
RELAY_PROGRAMS = frozenset({
    "cat", "echo", "printf", "head", "tail", "sed", "awk", "gawk", "mawk", "tr", "cut", "tee", "xargs", "env",
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "base64", "xxd", "od", "rev",
    "sort", "uniq", "grep", "egrep", "fgrep", "find", "curl", "wget", "nc", "ncat", "socat", "ssh", "sudo", "doas", "dd",
    "zcat", "gunzip", "bzcat", "xzcat", "openssl", "gpg", "eval", "exec", "command", "source", ".",
})
# Explicit, narrow trust exceptions for transparent package-managed generators.
# Attestation remains an assumption about emitted content, not its verification.
ATTESTABLE_GENERATORS = frozenset({"dircolors", "lesspipe"})
PROGRAM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
LIVE_ONLY_COLLECTORS = ("processes", "network", "kernel", "crossview")
# Probes that may run against an offline image: journalctl reading the image's own journal directory.
OFFLINE_ALLOWED_TOOLS = ("journalctl",)
SKIP_CODES = {"PROFILE_EXCLUDED": "excluded by profile", "BUDGET_EXHAUSTED": INCOMPLETE_CODES["BUDGET_EXHAUSTED"],
              "COLLECTOR_ERROR": "the collector raised and its observations were discarded"}


class Gaps:
    """Per-collector accumulator of coverage reason codes (closed vocabulary)."""

    def __init__(self) -> None:
        self.incomplete: Counter[str] = Counter()
        self.limits: Counter[str] = Counter()

    def add(self, code: str, count: int = 1) -> None:
        if code in INCOMPLETE_CODES:
            self.incomplete[code] += count
        elif code in SCOPE_LIMIT_CODES:
            self.limits[code] += count
        else:
            raise ValueError(f"unknown coverage reason code: {code}")


MAX_FILES_PER_COLLECTION = 2000
MAX_PROCESSES = 6000
MAX_FINDINGS = 350

# Package self-verification (pacman, apk: no verify command is run; the
# recorded digests are compared with the files on disk). Bounded to the parts
# of the tree where tampering changes what runs; libraries and data are not
# hashed within the scan budget. Conffile semantics: anything under /etc.
VERIFY_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/usr/lib/systemd/",
                   "/lib/systemd/", "/etc/", "/usr/lib/sysctl.d/", "/usr/lib/tmpfiles.d/")
VERIFY_MAX_FILES = 20000
VERIFY_MAX_BYTES = 512 * 1024 * 1024
VERIFY_MAX_FILE_BYTES = 8 * 1024 * 1024   # safe_read's own ceiling; larger files count as unverifiable
DPKG_DB_MAX_RECORDS = 20000
DPKG_DB_MAX_BYTES = 128 * 1024 * 1024
PACKAGE_DB_MAX_RECORDS = 20000
PACKAGE_DB_MAX_BYTES = 128 * 1024 * 1024
MTREE_MAX_COMPRESSED = 8 * 1024 * 1024
MTREE_MAX_DECOMPRESSED = 32 * 1024 * 1024
APK_DB_MAX_BYTES = 8 * 1024 * 1024   # safe_read's ceiling; a larger installed db is not parsed

# Cross-view consistency (Wang et al., "Strider GhostBuster", DSN 2005): the
# same fact read through two kernel interfaces must agree. A rootkit that
# hooks one of them (procfs readdir, procfs lookup, /proc/net, sock_diag)
# leaves a difference that needs no signature. Bounds keep the PID sweep
# inside the scan budget; candidates are re-checked to exclude races.
PID_SWEEP_MAX = 4_194_304            # kernel.pid_max ceiling on 64-bit Linux
PID_SWEEP_CHUNK = 65_536             # budget check interval
PID_RECHECK_DELAY = 0.05             # seconds between first and confirming probe
AUTH_LOG_FILES = ("/var/log/auth.log", "/var/log/secure", "/var/log/messages")
AUTH_LOG_MAX_BYTES = 8 * 1024 * 1024

# Hard whole-scan deadline (A-8). The cooperative budget turns an overrun into
# PARTIAL and keeps the observations; the hard deadline fires only after a
# grace period on top of it, so it catches a collector that is truly stuck in
# a blocking call (a FIFO, a hung filesystem) and could never reach a budget
# check. Such a collector is FAILED/BUDGET_EXHAUSTED and its observations are
# discarded, exactly like any other collector failure.
HARD_DEADLINE_GRACE_FRACTION = 0.05
HARD_DEADLINE_MIN_GRACE_SECONDS = 2.0


class DeadlineExpired(Exception):
    """Raised inside a running collector by the hard whole-scan deadline (SIGALRM)."""


MAX_CMDLINE_BYTES = 65_536
MAX_SHELL_FILES = 24
# Folder two levels above a native-messaging manifest names the browser.
NATIVE_HOST_OWNERS = {"google-chrome": "chrome", "chromium": "chromium", "Brave-Browser": "brave",
                      "microsoft-edge": "edge", ".mozilla": "firefox", "chrome": "chrome (system)",
                      "mozilla": "firefox (system)"}
JOURNAL_OUTPUT_LIMIT = 32 * 1024 * 1024
MAX_PREFERENCES_BYTES = 8 * 1024 * 1024
# Chromium Manifest::Location values (components/extensions); others are UNKNOWN.
CHROMIUM_LOCATIONS = {1: "INTERNAL", 2: "EXTERNAL_PREF", 3: "EXTERNAL_REGISTRY", 4: "UNPACKED",
                      5: "COMPONENT", 6: "EXTERNAL_PREF_DOWNLOAD", 7: "EXTERNAL_POLICY_DOWNLOAD",
                      8: "COMMAND_LINE", 9: "EXTERNAL_POLICY", 10: "EXTERNAL_COMPONENT"}
FIREFOX_SIGNED_STATES = {-2: "BROKEN", -1: "UNKNOWN", 0: "MISSING", 1: "PRELIMINARY", 2: "SIGNED",
                         3: "SYSTEM", 4: "PRIVILEGED"}
MAX_EXE_HASH_BYTES = 64 * 1024 * 1024


def _read_at(dirfd: int, name: str, limit: int) -> bytes:
    """Bounded read of a file relative to a pinned directory fd (no symlink follow)."""
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dirfd)
    try:
        chunks = bytearray()
        while len(chunks) < limit:
            chunk = os.read(fd, min(65536, limit - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)
    finally:
        os.close(fd)


def _in_journal_reader_group() -> bool:
    """Members of adm/systemd-journal read the system journal; others see only their own."""
    try:
        import grp
        names = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    except (KeyError, OSError):
        return False
    return bool(names & {"adm", "systemd-journal"})


def _parse_proc_stat(raw: bytes) -> tuple[int, int] | None:
    """(ppid, starttime) from /proc/<pid>/stat; comm may contain spaces and ')'."""
    try:
        fields = raw.rsplit(b")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _live_pid_probe(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _hex_endpoint_port(field: str) -> int | None:
    """Port of a /proc/net/{tcp,udp}{,6} local_address field (hex, host order)."""
    _addr, _, port = field.rpartition(":")
    try:
        return int(port, 16)
    except ValueError:
        return None


def _proc_listener_endpoint(table: str, field: str) -> tuple[str, str, int] | None:
    """Decode Linux /proc/net local_address, including IPv6 32-bit LE words.

    No raw local address is ever emitted into a persisted finding.
    """
    addr, sep, port = field.partition(":")
    # bytes.fromhex plus ipaddress validate both hex syntax and exact
    # address width. Repeating these checks here did not strengthen safety.
    if not sep:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
        return None
    try:
        raw = bytes.fromhex(addr)
        if table.endswith("6"):
            # Linux prints each 32-bit IPv6 word in little-endian order.
            ordered = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            host = str(ipaddress.IPv6Address(ordered))
            family = "6"
        else:
            host = str(ipaddress.IPv4Address(raw[::-1]))
            family = "4"
    except ValueError:
        return None
    return (table.rstrip("6") + family, host, int(port, 16))


def _ss_listener_endpoints(output: str) -> set[tuple[str, str, int]] | None:
    """Keep exact local address/family/port; reject an ambiguous ss table.

    An asterisk hostname, scope-qualified IPv6 address or malformed address
    cannot prove absence in the other view. Do not reduce it to (proto, port).
    """
    result: set[tuple[str, str, int]] = set()
    for row in output.splitlines():
        fields = row.split()
        if not fields:
            continue
        if fields[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        # A truncated known-protocol row is not proof of socket absence.
        if len(fields) < 2:
            return None
        if fields[1] not in ("LISTEN", "UNCONN"):
            continue
        if len(fields) < 5:
            return None
        addr, sep, port_text = fields[4].rpartition(":")
        if not sep or not re.fullmatch(r"[0-9]{1,5}", port_text):
            return None
        if addr.startswith("[") and addr.endswith("]"):
            addr = addr[1:-1]
        if not addr or "%" in addr:
            return None
        try:
            host = ipaddress.ip_address(addr)
        except ValueError:
            return None
        family = "6" if host.version == 6 else "4"
        if fields[0].endswith("6") and family != "6":
            return None
        port = int(port_text)
        if port > 65535:
            return None
        result.add((fields[0].rstrip("6") + family, str(host), port))
    return result

def _proc_mount_has_hidepid(raw: bytes) -> bool | None:
    """Return True (restricted), False (verified unrestricted), or None (unknown).

    The kernel's mountinfo format requires mount options, the '-' separator,
    filesystem type and superblock options. An absent/malformed procfs record
    cannot prove a user has unrestricted process-list visibility.
    """
    if not raw or b"\x00" in raw:
        return None
    seen_proc = False
    for line in raw.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 5:
            return None
        if fields[4] != "/proc":
            continue
        seen_proc = True
        if "-" not in fields:
            return None
        dash = fields.index("-")
        # dash >= 6 and len == dash + 4 establish the 10-field minimum.
        # Duplicating that bound above makes an unobservable mutant.
        if dash < 6 or len(fields) != dash + 4 or fields[dash + 1] != "proc":
            return None
        options = fields[5].split(",") + fields[dash + 3].split(",")
        for option in options:
            if not option.startswith("hidepid="):
                continue
            mode = option.partition("=")[2]
            if mode in ("1", "2", "4", "invisible", "ptraceable"):
                return True
            if mode != "0":
                return None
    return False if seen_proc else None


class Audit:
    def __init__(self, scope: str, target_user: str | None = None, incident_at: str | None = None,
                 profile: str = "standard", max_seconds: int | None = None, root: Path | str = "/",
                 offline: bool = False):
        # Every system path is resolved under `root` (default "/": the live
        # host). A fixture host emulating a live system points root elsewhere
        # and keeps offline=False; a mounted image is scanned with offline=True:
        # no live kernel is observed, no probe describes it, and users and
        # homes come from the image's own /etc/passwd.
        self.root = Path(root)
        self.proc_root = self.root / "proc"
        self.offline = bool(offline)
        if self.offline and self.root.absolute() == Path("/"):
            raise ValueError("offline mode needs a root other than /")
        if scope not in ("user", "system"):
            raise ValueError("scope must be user or system")
        if not self.offline:
            if scope == "system" and os.geteuid() != 0:
                raise PermissionError("System scope requires explicit root invocation")
            if scope == "user" and os.geteuid() == 0:
                raise PermissionError("Run user scope without root privileges")
        if (scope == "system" or self.offline) and not target_user:
            raise ValueError("System scope and offline images require --target-user")
        target = target_user or pwd.getpwuid(os.getuid()).pw_name
        entry = self._image_passwd(target) if self.offline else pwd.getpwnam(target)
        if entry.pw_uid == 0:
            raise ValueError("Refusing to treat root as browser user")
        self.profile = profile
        self.profile_config = config_for(profile)
        if max_seconds is not None and not 5 <= max_seconds <= 600:
            raise ValueError("--max-seconds must be 5..600")
        self.max_seconds = max_seconds or self.profile_config["duration_seconds"]
        self.deadline: float | None = None
        self.phase_timings: dict[str, int] = {}
        self.current_phase: str | None = None
        self.scope = scope
        self.target_user = target
        self.uid = entry.pw_uid
        self.home = Path(entry.pw_dir)
        self.started_utc = utc_now()
        self.findings: list[dict] = []
        self.coverage: list[dict] = []
        self.commands: list[dict] = []
        self.stats: dict[str, Any] = {}
        self.private_index: dict[str, str] = {}
        self.baseline: dict[str, list[str]] = {
            "process_exe_hashes": [], "listeners": [], "systemd_units": [],
            "cron_entry_hashes": [], "ssh_key_fingerprints": [],
            "browser_extensions": [], "native_hosts": [],
        }
        self._next = 0
        self.dropped_findings = 0
        self._collector_active = False
        self.hard_deadline_fired = False
        # Existence oracle for the PID sweep; replaced by fixtures. kill(pid, 0)
        # sends no signal: EPERM means "exists, not ours", ESRCH means absent.
        self.pid_probe: Callable[[int], bool] = _live_pid_probe
        self.suspicious_exec_pids: set[int] = set()
        self.native_hosts_by_extension: dict[str, set[str]] = {}
        self._dpkg_index: dict[str, str] | None = None
        self._pacman_index: dict[str, tuple[str, str]] | None = None
        self._apk_index: dict[str, tuple[str, str]] | None = None
        self._package_db_gaps: dict[str, Counter[str]] = {}
        boot, _ = safe_read(self.proc_root / "sys/kernel/random/boot_id", 64)
        self.boot_id = boot.decode("ascii", "replace").strip() if boot else "UNAVAILABLE"
        self.incident_at = None
        if incident_at:
            try:
                anchor = dt.datetime.fromisoformat(incident_at.replace("Z", "+00:00"))
            except (TypeError, ValueError) as exc:
                raise ValueError("--incident-at must be ISO 8601 with timezone") from exc
            if anchor.tzinfo is None:
                raise ValueError("--incident-at must include timezone offset (e.g. +02:00)")
            self.incident_at = anchor.astimezone(dt.timezone.utc)

    def _image_passwd(self, user: str) -> Any:
        """The image's own /etc/passwd entry for `user` (no NSS of the live host)."""
        raw, status = safe_read(self.sys("/etc/passwd"), 4 * 1024 * 1024)
        if raw is None:
            raise ValueError(f"offline image has no readable /etc/passwd ({status})")
        for line in raw.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if len(fields) >= 7 and fields[0] == user:
                try:
                    return SimpleNamespace(pw_name=user, pw_uid=int(fields[2]), pw_dir=str(self.sys(fields[5])))
                except ValueError as exc:
                    raise ValueError("offline image passwd entry is malformed") from exc
        raise ValueError(f"user {user!r} is not in the image's /etc/passwd")

    def sys(self, path: str) -> Path:
        """Absolute system path resolved under the scan root."""
        return self.root / path.lstrip("/")

    def image_path(self, path: Path) -> str:
        """Path as the inspected system itself names it (root prefix removed)."""
        try:
            return "/" + path.absolute().relative_to(self.root.absolute()).as_posix()
        except ValueError:
            return path.as_posix()

    def source(self, text: str | Path) -> str:
        """Public reports contain an opaque ID; path only in local private_index."""
        raw = str(text)
        ref = "src_" + d.digest(raw, 24)
        self.private_index[ref] = raw
        return ref

    def finding(self, rule: str, severity: str, hypothesis: str, source: str | Path,
                evidence: dict | None = None, kind: str = "INDICATOR", attack: str = "",
                observed: dict | None = None) -> None:
        """Record a finding. `evidence` is canonical (hashed into the finding ID);
        `observed` is per-run attribution (PIDs, times, hashes) kept beside it so
        the same observation keeps the same ID across scans."""
        if len(self.findings) >= MAX_FINDINGS:
            self.dropped_findings += 1
            return
        self._next += 1
        if kind not in ("INDICATOR", "EXPOSURE", "HARDENING", "CONTEXT"):
            raise ValueError("bad finding kind")
        self.findings.append({
            "id": f"F{self._next:04d}", "rule": rule, "severity": severity,
            "kind": kind, "hypothesis": hypothesis, "source_ref": self.source(source),
            "evidence": evidence or {}, "classification": "SUSPICIOUS_UNCONFIRMED" if kind == "INDICATOR" else "REQUIRES_REVIEW",
            "attack_technique": attack or None,
            "confirmation": "NOT_ESTABLISHED", "alternative_explanation": "Requires operator review and corroboration",
            "observations": [observed] if observed else [],
        })

    def checked(self, name: str, status: str, details: str, sources: int | None = None,
                gaps: Gaps | None = None, reasons: Iterable[str] = ()) -> None:
        if status not in ("COMPLETED", "PARTIAL", "FAILED", "UNAVAILABLE", "SKIPPED"):
            raise ValueError(status)
        gaps = gaps if gaps is not None else Gaps()
        for code in reasons:
            if code in SKIP_CODES and code not in INCOMPLETE_CODES:
                gaps.incomplete[code] += 1
            else:
                gaps.add(code)
        if status == "COMPLETED" and gaps.incomplete:
            raise ValueError("COMPLETED check cannot carry incompleteness reasons")
        if status == "PARTIAL" and not gaps.incomplete:
            raise ValueError("PARTIAL check requires at least one incompleteness reason")
        item: dict[str, Any] = {"check": name, "status": status, "details": details,
                                "reason_codes": dict(sorted(gaps.incomplete.items())),
                                "scope_limits": dict(sorted(gaps.limits.items()))}
        if sources is not None:
            item["sources_inspected"] = sources
        self.coverage.append(item)

    def conclude(self, name: str, details: str, gaps: Gaps, sources: int | None = None) -> None:
        """Status follows from evidence: PARTIAL iff an incompleteness reason exists."""
        self.checked(name, "PARTIAL" if gaps.incomplete else "COMPLETED", details, sources, gaps)

    def read_gap(self, path: Path, status: str, gaps: Gaps) -> None:
        """Classify a failed safe_read(). ABSENT is not a gap: nothing to inspect."""
        if status in ("COMPLETED", "ABSENT"):
            return
        if status == "PERMISSION_DENIED":
            try:
                owner = path.lstat().st_uid
            except OSError:
                owner = None
            foreign = self.scope == "user" and owner is not None and owner != self.uid
            gaps.add("OTHER_ACCOUNTS_NOT_VISIBLE" if foreign else "PERMISSION_DENIED")
        elif status == "TOO_LARGE":
            gaps.add("INPUT_TRUNCATED")
        elif status == "SYMLINK_OR_NOT_DIRECTORY":
            gaps.add("SYMLINK_NOT_FOLLOWED")
        elif status == "NOT_REGULAR":
            gaps.add("MALFORMED_INPUT")
        else:
            gaps.add("READ_FAILED")

    @staticmethod
    def command_gap(result: dict, gaps: Gaps) -> None:
        status, error = result["status"], result.get("error", "")
        if status == "COMPLETED":
            return
        if status == "UNAVAILABLE":
            gaps.add("TOOL_MISSING")
        elif status == "SKIPPED" and error == "OFFLINE_IMAGE":
            gaps.add("LIVE_ONLY_NOT_IN_OFFLINE_IMAGE")
        elif status == "SKIPPED":
            gaps.add("BUDGET_EXHAUSTED")
        elif result.get("truncated"):
            gaps.add("INPUT_TRUNCATED")
        elif "timeout" in error:
            gaps.add("TIMEOUT")
        else:
            gaps.add("TOOL_FAILED")

    def command(self, tool: str, args: list[str], timeout: float = 12, limit: int = 2*1024*1024) -> dict:
        if not _allowed_audit_invocation(tool, args):
            raise PermissionError("Collector command is not an approved read-only probe")
        if self.offline and tool not in OFFLINE_ALLOWED_TOOLS:
            # A probe would describe the live host, not the image: refused, and
            # reported as a scope limit rather than a missing tool.
            return {"status": "SKIPPED", "stdout": "", "stderr": "", "exit": None, "elapsed_ms": 0,
                    "truncated": False, "error": "OFFLINE_IMAGE", "residual_killed": False}
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "SKIPPED", "stdout": "", "exit": None,
                        "elapsed_ms": 0, "truncated": False, "error": "global runtime budget exhausted"}
            timeout = min(timeout, remaining)
        r = run_command(tool, args, timeout=timeout, limit=limit)
        self.commands.append({
            "time_utc": utc_now(), "program": tool, "args": args,
            "status": r["status"], "exit": r["exit"], "elapsed_ms": r["elapsed_ms"],
            "truncated": r["truncated"], "error": r["error"],
        })
        # Never persist raw command stdout.
        return r

    def over_budget(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def _rollback_collector(self, checkpoint: tuple, coverage_len: int) -> None:
        """Atomically discard uncommitted evidence from a failed collector."""
        (finding_count, self.dropped_findings, self._next,
         self.stats, self.baseline, self.private_index,
         self.suspicious_exec_pids) = checkpoint
        del self.findings[finding_count:]
        del self.coverage[coverage_len:]

    def hard_deadline_seconds(self) -> float:
        return self.max_seconds + max(HARD_DEADLINE_MIN_GRACE_SECONDS,
                                      HARD_DEADLINE_GRACE_FRACTION * self.max_seconds)

    def _arm_hard_deadline(self, seconds: float) -> tuple[Any] | None:
        """Install a one-shot SIGALRM that raises DeadlineExpired inside a collector.

        Signals are delivered to the main thread only, so elsewhere the scan
        falls back to the cooperative budget and records that it did. Outside a
        collector (bookkeeping between phases) the alarm only sets a flag: the
        next budget check sees the expired deadline.
        """
        if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
            self.stats["hard_deadline"] = {"armed": False, "reason": "NOT_MAIN_THREAD"}
            return None

        def on_alarm(_signum: int, _frame: object) -> None:
            self.hard_deadline_fired = True
            if self._collector_active:
                raise DeadlineExpired()

        previous = signal.signal(signal.SIGALRM, on_alarm)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        self.stats["hard_deadline"] = {"armed": True, "seconds": round(seconds, 3)}
        return (previous,)

    @staticmethod
    def _disarm_hard_deadline(armed: tuple[Any] | None) -> None:
        if armed is None:
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        previous = armed[0]
        signal.signal(signal.SIGALRM, previous if previous is not None else signal.SIG_DFL)

    def scan(self, progress: Callable[[str], None] | None = None) -> None:
        """Run collectors in fixed order. `progress` receives operator-facing
        phase lines; it must not influence collection or analysis."""
        def emit(line: str) -> None:
            # Progress is advisory: its failure must not change collection.
            if progress is None:
                return
            try:
                progress(line)
            # A UI callback must never alter collection, so any failure is swallowed.
            except Exception:  # noqa: BLE001  # nosec B110
                pass
        started = time.monotonic()
        self.deadline = started + self.max_seconds
        selected = [n for n in COLLECTOR_ORDER if n in self.profile_config["checks"]]
        armed = self._arm_hard_deadline(self.hard_deadline_seconds())
        try:
            for name in COLLECTOR_ORDER:
                if name not in self.profile_config["checks"]:
                    self.checked(name, "SKIPPED", f"Excluded by {self.profile} profile; not a negative result",
                                 reasons=["PROFILE_EXCLUDED"])
                    continue
                if self.offline and name in LIVE_ONLY_COLLECTORS:
                    self.checked(name, "SKIPPED", "Offline image: no running kernel to observe; not a negative result",
                                 reasons=["LIVE_ONLY_NOT_IN_OFFLINE_IMAGE"])
                    continue
                if self.over_budget():
                    self.checked(name, "SKIPPED", "Runtime budget exhausted before collector started",
                                 reasons=["BUDGET_EXHAUSTED"])
                    emit(f"{name}: SKIPPED (runtime budget exhausted)")
                    continue
                previous_checks = len(self.coverage)
                tick = time.monotonic()
                self.current_phase = name
                emit(f"[{selected.index(name) + 1}/{len(selected)}] {name}: start")
                # A failed collector must not contribute findings, baseline state or
                # partially computed metrics. Keep its command audit for provenance.
                checkpoint = (
                    len(self.findings), self.dropped_findings, self._next,
                    copy.deepcopy(self.stats), copy.deepcopy(self.baseline),
                    dict(self.private_index), set(self.suspicious_exec_pids),
                )
                try:
                    try:
                        # The alarm may raise only while this flag is set, so the
                        # exception can surface nowhere but in this except clause.
                        self._collector_active = True
                        getattr(self, name)()
                    finally:
                        self._collector_active = False
                except DeadlineExpired:
                    self._rollback_collector(checkpoint, previous_checks)
                    self.checked(name, "FAILED", "hard whole-scan deadline interrupted the collector; "
                                 "discarded incomplete observations", reasons=["BUDGET_EXHAUSTED"])
                    self.stats[f"{name}_exception"] = "DeadlineExpired"
                except Exception as exc:
                    self._rollback_collector(checkpoint, previous_checks)
                    self.checked(name, "FAILED", f"collector failed; discarded incomplete observations ({type(exc).__name__})",
                                 reasons=["COLLECTOR_ERROR"])
                    self.stats[f"{name}_exception"] = type(exc).__name__
                else:
                    if not any(c["check"] == name for c in self.coverage[previous_checks:]):
                        self._rollback_collector(checkpoint, previous_checks)
                        self.checked(name, "FAILED", "Collector returned without a coverage result; discarded incomplete observations",
                                     reasons=["COLLECTOR_ERROR"])
                    elif self.over_budget():
                        for c in self.coverage[previous_checks:]:
                            if c["check"] == name and c["status"] in ("COMPLETED", "PARTIAL"):
                                c["status"] = "PARTIAL"
                                c["reason_codes"]["BUDGET_EXHAUSTED"] = c["reason_codes"].get("BUDGET_EXHAUSTED", 0) + 1
                                c["reason_codes"] = dict(sorted(c["reason_codes"].items()))
                                if "runtime budget exceeded" not in c["details"]:
                                    c["details"] += "; runtime budget exceeded"
                self.phase_timings[name] = max(0, int((time.monotonic() - tick) * 1000))
                states = [c["status"] for c in self.coverage[previous_checks:] if c["check"] == name]
                emit(f"{name}: {states[-1] if states else 'UNKNOWN'} ({self.phase_timings[name]} ms)")
        finally:
            self._disarm_hard_deadline(armed)
        self.current_phase = None
        self._correlate_debug_ports()
        if self.dropped_findings:
            self.checked("finding_capacity", "PARTIAL", f"{self.dropped_findings} findings omitted (limit {MAX_FINDINGS})",
                         reasons=["ENUMERATION_LIMIT"])
        self.stats["runtime"] = {"elapsed_ms": int((time.monotonic() - started) * 1000),
                                  "budget_seconds": self.max_seconds,
                                  "hard_deadline_fired": self.hard_deadline_fired,
                                  "phase_elapsed_ms": self.phase_timings,
                                  "profile": self.profile}
        self.deadline = None

    def environment(self) -> None:
        raw, status = safe_read(self.sys("/etc/os-release"), limit=16_384)
        os_release_source = "/etc/os-release"
        if raw is None:
            # /etc/os-release -> ../usr/lib/os-release is the normal systemd
            # arrangement on Ubuntu. Do NOT relax the general no-symlink read
            # policy; read the fixed vendor path independently instead.
            fallback, fallback_status = safe_read(self.sys("/usr/lib/os-release"), limit=16_384)
            if fallback is not None:
                raw, status = fallback, fallback_status
                os_release_source = "/usr/lib/os-release"
        os_release = {}
        if raw:
            for line in raw.decode("utf-8", "replace").splitlines():
                if line.startswith(("ID=", "VERSION_ID=", "PRETTY_NAME=")):
                    k, val = line.split("=", 1)
                    os_release[k] = val.strip('"')[:120]
        kernel = self.command("uname", ["-r"])
        self.stats["host"] = {
            "os_release": os_release,
            "os_release_source": os_release_source,
            "kernel": kernel["stdout"].strip()[:120] if kernel["status"] == "COMPLETED" else "UNKNOWN",
            "scope": self.scope,
            "target_uid": self.uid,
            "started_utc": self.started_utc,
            "incident_at_utc": self.incident_at.isoformat() if self.incident_at else None,
        }
        user_dot_ssh = self.home / ".ssh"
        if user_dot_ssh.is_dir() and not user_dot_ssh.is_symlink():
            mode = stat.S_IMODE(user_dot_ssh.stat().st_mode)
            if mode & 0o077:
                self.finding("SSH_DIRECTORY_OVERPERMISSIVE", "low", "Excessive SSH directory access", user_dot_ssh,
                             {"mode_oct": oct(mode)}, kind="HARDENING")
        for f in ("/proc/sys/kernel/yama/ptrace_scope", "/proc/sys/kernel/unprivileged_bpf_disabled",
                  "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict"):
            value, _ = safe_read(self.sys(f), 64)
            if value is not None:
                self.stats[f"sysctl_{Path(f).name}"] = value.decode("ascii", "replace").strip()
        gaps = Gaps()
        if raw is None:
            self.read_gap(self.sys(os_release_source), status, gaps)
            if not gaps.incomplete:
                gaps.add("READ_FAILED")
        self.command_gap(kernel, gaps)
        self.conclude("environment", "Local OS/kernel metadata (fixed vendor fallback for os-release symlink), selected policy sysctls; no runtime attestation", gaps)

    def _process_identity(self, pid: int, dirfd: int) -> dict | None:
        """Identity of one process read through a pinned /proc/<pid> dirfd.

        A dirfd pins the observed process: if it exits and the PID is reused,
        reads through this fd fail instead of returning the newcomer. The start
        time (stat field 22, clock ticks since boot) plus boot_id is recorded so
        a later reader can tell a reused PID apart. Returns None if it vanished.
        """
        try:
            raw = _read_at(dirfd, "stat", 4096)
        except OSError:
            return None
        parsed = _parse_proc_stat(raw)
        return {"pid": pid, "ppid": parsed[0] if parsed else None,
                "start_ticks": parsed[1] if parsed else None}

    def _executable_identity(self, dirfd: int) -> dict:
        """Metadata of the mapped executable (works for deleted files too)."""
        try:
            info = os.stat("exe", dir_fd=dirfd)
        except OSError:
            return {"status": "UNAVAILABLE"}
        meta: dict[str, Any] = {"dev_ino": f"{info.st_dev}:{info.st_ino}", "size": info.st_size,
                                "owner_uid": info.st_uid, "mode_oct": oct(stat.S_IMODE(info.st_mode)),
                                "mtime_utc": dt.datetime.fromtimestamp(int(info.st_mtime), dt.timezone.utc).isoformat()}
        if info.st_size > MAX_EXE_HASH_BYTES:
            meta["sha256"] = "NOT_HASHED_SIZE_LIMIT"
            return meta
        try:
            fd = os.open("exe", os.O_RDONLY, dir_fd=dirfd)
        except OSError:
            meta["sha256"] = "UNREADABLE"
            return meta
        try:
            h = hashlib.sha256()
            while chunk := os.read(fd, 1 << 20):
                h.update(chunk)
            meta["sha256"] = h.hexdigest()
        except OSError:
            meta["sha256"] = "UNREADABLE"
        finally:
            os.close(fd)
        return meta

    def _attribution(self, root: Path, pid: int, dirfd: int, ident: dict, uid: int, exe: str) -> dict:
        """Private attribution captured at observation time (survives process exit)."""
        parent: dict[str, Any] = {"pid": ident.get("ppid")}
        if ident.get("ppid"):
            try:
                pfd = os.open(str(root / str(ident["ppid"])), os.O_RDONLY | os.O_DIRECTORY)
            except OSError:
                parent["status"] = "UNAVAILABLE"
            else:
                try:
                    pident = self._process_identity(ident["ppid"], pfd)
                    parent["start_ticks"] = pident.get("start_ticks") if pident else None
                    try:
                        parent["exe_name"] = Path(os.readlink("exe", dir_fd=pfd)).name[:80]
                    except OSError:
                        parent["exe_name"] = "UNAVAILABLE"
                finally:
                    os.close(pfd)
        return {"pid": pid, "ppid": ident.get("ppid"), "uid": uid,
                "start_ticks": ident.get("start_ticks"), "boot_id": self.boot_id,
                "exe_name": Path(exe.removesuffix(" (deleted)")).name[:80],
                "exe_ref": self.source(exe), "executable": self._executable_identity(dirfd),
                "parent": parent, "observed_utc": utc_now(),
                "package_owner": "NOT_COLLECTED"}

    def processes(self) -> None:
        root = self.proc_root
        gaps = Gaps()
        total = 0
        denied = foreign = protected = disappeared = truncated_cmdlines = 0
        exeids: set[str] = set()
        browser_seen = 0
        try:
            names = sorted((e.name for e in root.iterdir() if e.name.isdigit()), key=int)
        except OSError:
            gaps.add("READ_FAILED")
            names = []
        for pid_text in names:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                break
            total += 1
            if total > self.profile_config["max_processes"]:
                gaps.add("ENUMERATION_LIMIT")
                break
            pid = int(pid_text)
            try:
                dirfd = os.open(str(root / pid_text), os.O_RDONLY | os.O_DIRECTORY)
            except OSError:
                disappeared += 1
                continue
            try:
                ident = self._process_identity(pid, dirfd) or {"pid": pid, "ppid": None, "start_ticks": None}
                try:
                    status_raw = _read_at(dirfd, "status", 16_384)
                except PermissionError:
                    denied += 1
                    continue
                except OSError:
                    disappeared += 1
                    continue
                data = status_raw.decode("utf-8", "replace")
                uid_match = re.search(r"^Uid:\s+(\d+)", data, re.M)
                if uid_match is None:
                    continue
                uid = int(uid_match.group(1))
                uid_fields = re.search(r"^Uid:[ \t]+([\d \t]+)$", data, re.M)
                uid_set = {int(x) for x in uid_fields.group(1).split()[:4]} if uid_fields else {uid}
                if ident["ppid"] is None:
                    ppid_match = re.search(r"^PPid:\s+(\d+)", data, re.M)
                    ident["ppid"] = int(ppid_match.group(1)) if ppid_match else None
                try:
                    exe = os.readlink("exe", dir_fd=dirfd)
                except PermissionError:
                    # In user scope, other accounts' (or setuid-transitioned)
                    # executables are invisible by design; own non-dumpable
                    # processes are hidden by the kernel and need system scope.
                    if self.scope == "user" and uid_set != {self.uid}:
                        foreign += 1
                    elif self.scope == "user":
                        protected += 1
                    else:
                        denied += 1
                    continue
                except OSError:
                    disappeared += 1
                    continue
                exeids.add(d.digest(exe))
                for rule, severity in d.classify_executable(exe, uid, deleted=exe.endswith(" (deleted)")):
                    if rule == "EXECUTABLE_IN_VOLATILE_PATH":
                        self.suspicious_exec_pids.add(pid)
                    # Source is the executable, not /proc/<pid>: identity must not depend on the PID.
                    self.finding(rule, severity, "Potential unauthorized execution or persistence", exe,
                                 {"uid": uid, "exe_id": d.digest(exe)},
                                 observed=self._attribution(root, pid, dirfd, ident, uid, exe))
                if any(b in exe.lower() for b in ("chrome", "chromium", "firefox", "brave")):
                    browser_seen += 1
                    try:
                        cmdraw = _read_at(dirfd, "cmdline", MAX_CMDLINE_BYTES + 1)
                    except OSError:
                        disappeared += 1
                        continue
                    if len(cmdraw) > MAX_CMDLINE_BYTES:
                        # Flags beyond the bound are unseen: say so instead of reporting clean.
                        truncated_cmdlines += 1
                        cmdraw = cmdraw[:MAX_CMDLINE_BYTES]
                    args = [x.decode("utf-8", "replace") for x in cmdraw.split(b"\0") if x]
                    review = d.browser_flag_review(args)
                    if review["flags"]:
                        self.finding("UNSAFE_BROWSER_LAUNCH_FLAG", "medium", review["hypothesis"], exe,
                                     {"exe_id": d.digest(exe), "flags": review["flags"],
                                      "sandbox_reduced": review["sandbox_reduced"],
                                      "debug_channel": review["debug_channel"],
                                      "debug_port": review["debug_port"],
                                      "debug_port_listener": "NOT_CORRELATED" if review["debug_port"] else None},
                                     kind="EXPOSURE", observed=self._attribution(root, pid, dirfd, ident, uid, exe))
            finally:
                os.close(dirfd)
        if denied:
            gaps.add("PERMISSION_DENIED", denied)
        if foreign:
            gaps.add("OTHER_ACCOUNTS_NOT_VISIBLE", foreign)
        if protected:
            gaps.add("REQUIRES_SYSTEM_SCOPE", protected)
        if disappeared:
            gaps.add("SOURCE_VANISHED", disappeared)
        if truncated_cmdlines:
            gaps.add("INPUT_TRUNCATED", truncated_cmdlines)
        self.baseline["process_exe_hashes"] = sorted(exeids)
        self.stats["processes"] = {"enumerated": min(total, self.profile_config["max_processes"]), "denied": denied,
                                   "other_accounts_not_visible": foreign, "protected_own_processes": protected,
                                   "disappeared": disappeared,
                                   "browser_processes": browser_seen, "browser_cmdlines_truncated": truncated_cmdlines}
        self.conclude("processes", "Live /proc metadata only; process lists cannot prove absence of rootkits; command lines not exported",
                      gaps, min(total, self.profile_config["max_processes"]))

    def network(self) -> None:
        r = self.command("ss", ["-H", "-tuna", "-p"], timeout=15)
        gaps = Gaps()
        self.command_gap(r, gaps)
        if r["status"] not in ("COMPLETED", "PARTIAL"):
            self.checked("network", "UNAVAILABLE" if r["status"] == "UNAVAILABLE" else "FAILED",
                         "ss unavailable or failed; no active network scan", gaps=gaps)
            return
        sockets = d.parse_ss(r["stdout"])
        self.listening_ports: dict[str, set[str]] = {}
        for sock in sockets:
            if sock["state"] == "LISTEN":
                self.listening_ports.setdefault(str(sock["local_port"]), set()).add(sock["local_class"])
        counts = Counter(x["state"] for x in sockets)
        exposed = []
        observed = set()
        for s in sockets:
            if s["state"] in ("LISTEN", "UNCONN") and s["local_class"] in ("wildcard", "public", "private"):
                key = f"{s['proto']}/{s['local_port']}/{s['local_class']}"
                observed.add(key)
                exposed.append({"proto": s["proto"], "port": s["local_port"], "bind": s["local_class"]})
                if s["state"] == "LISTEN" and s["local_port"] in ("22", "23", "3389", "5900", "5901", "5555"):
                    self.finding("REMOTE_ACCESS_PORT_EXPOSED", "medium", "Remote access listener requires authorization review", "ss://" + key,
                                 {"protocol": s["proto"], "port": s["local_port"], "bind": s["local_class"]}, kind="EXPOSURE", attack="T1021")
        for s in sockets:
            if s["state"] in ("ESTAB", "ESTABLISHED") and s["remote_class"] == "public" and self.suspicious_exec_pids.intersection(s["pids"]):
                self.finding("TEMP_PROCESS_PUBLIC_EGRESS", "high", "A process executing from volatile storage has an observed public network connection", "ss://volatile-process",
                             {"pid_count": len(self.suspicious_exec_pids.intersection(s["pids"])), "remote_endpoint_id": s["remote_id"]},
                             kind="INDICATOR")
        # Raw network endpoints are kept only in the local private index, never in public reports.
        for line in r["stdout"].splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[0] in ("tcp", "udp", "tcp6", "udp6"):
                remote = fields[5]
                if d.endpoint_class(remote) in ("public", "private"):
                    self.private_index["net_" + d.digest(remote)] = remote
        self.baseline["listeners"] = sorted(observed)
        self.stats["network"] = {"socket_count": len(sockets), "states": dict(counts),
                                 "listeners": exposed[:150], "listeners_truncated": max(0, len(exposed)-150),
                                 "process_attribution_available": sum(s["has_process_info"] for s in sockets)}
        missing_owner = sum(s["state"] == "LISTEN" and not s["has_process_info"] for s in sockets)
        self.stats["network"]["listeners_without_process_identity"] = missing_owner
        if missing_owner:
            # ss -p only names processes this account may inspect.
            gaps.add("OTHER_ACCOUNTS_NOT_VISIBLE" if self.scope == "user" else "ATTRIBUTION_UNAVAILABLE", missing_owner)
        self.conclude("network", "One-time ss snapshot; remote endpoint literals only in private_index.json; no packet history",
                      gaps, len(sockets))

    def _correlate_debug_ports(self) -> None:
        """Attach the observed listener state to debug-port findings.

        Runs after all collectors so a rolled-back network collector cannot leave
        a half-applied correlation; without a network observation it says UNKNOWN.
        """
        network_rows = [c for c in self.coverage if c["check"] == "network"]
        network_state = network_rows[-1]["status"] if network_rows else None
        network_ok = network_state in ("COMPLETED", "PARTIAL")
        network_complete = network_state == "COMPLETED"
        listeners = getattr(self, "listening_ports", {}) if network_ok else None
        for f in self.findings:
            ev = f.get("evidence", {})
            if f.get("rule") != "UNSAFE_BROWSER_LAUNCH_FLAG" or not ev.get("debug_port"):
                continue
            if listeners is None or ev["debug_port"] == "INVALID":
                ev["debug_port_listener"] = "UNKNOWN"
            elif ev["debug_port"] not in listeners:
                # Partial ss output can establish a seen listener, never its absence.
                ev["debug_port_listener"] = "NOT_OBSERVED" if network_complete else "UNKNOWN"
            elif listeners[ev["debug_port"]] <= {"loopback"}:
                ev["debug_port_listener"] = "LISTENING_LOOPBACK_ONLY"
            else:
                ev["debug_port_listener"] = "LISTENING_BEYOND_LOOPBACK"

    def _mtime_near_incident(self, path: Path) -> bool | None:
        if not self.incident_at:
            return None
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
            return abs((mtime - self.incident_at).total_seconds()) <= 72 * 3600
        except OSError:
            return None

    def _files(self, bases: Iterable[Path], extensions: set[str] | None = None,
               recursive: bool = False, limit: int = MAX_FILES_PER_COLLECTION,
               gaps: Gaps | None = None, follow_root_links: bool = False) -> tuple[list[Path], bool]:
        """Bounded, no-follow enumeration. Returns (files, incomplete).

        A symlink is never followed. It is covered when its target resolves to
        /dev/null (a masked unit) or inside one of the inspected roots, because
        the target itself is enumerated there; otherwise it is a coverage gap.
        """
        bases = list(bases)
        gaps = gaps if gaps is not None else Gaps()
        roots = []
        for base in bases:
            try:
                if base.is_dir() and not base.is_symlink():
                    roots.append(os.path.realpath(base))
            except OSError:
                pass

        def covered(link: Path) -> bool:
            target = os.path.realpath(link)
            return target == os.devnull or any(target == r or target.startswith(r + os.sep) for r in roots)

        def root_controlled_target(link: Path) -> Path | None:
            """Target of a packaged link (e.g. /etc/... -> /usr/share/...).

            Followed only if the link and every component of the resolved
            target are root-owned and not group/world-writable, so no
            unprivileged account can redirect the read.
            """
            if not follow_root_links:
                return None
            try:
                if link.lstat().st_uid != 0:
                    return None
                target = Path(os.path.realpath(link))
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode):
                    return None
                for part in (target, *target.parents):
                    meta = part.lstat()
                    if meta.st_uid != 0 or meta.st_mode & 0o022:
                        return None
            except OSError:
                return None
            return target
        out: list[Path] = []
        incomplete = False
        visits = 0
        visit_budget = self.profile_config["max_file_visits"]

        def stop(code: str) -> tuple[list[Path], bool]:
            gaps.add(code)
            return out, True
        for base in bases:
            if self.over_budget():
                return stop("BUDGET_EXHAUSTED")
            try:
                if base.is_symlink():
                    incomplete = True
                    gaps.add("SYMLINK_NOT_FOLLOWED")
                    continue
                if not base.is_dir():
                    continue
                # os.walk can silently skip unreadable nested folders unless
                # onerror is installed: a skipped subtree is a coverage gap.
                def walk_error(exc: OSError) -> None:
                    nonlocal incomplete
                    incomplete = True
                    gaps.add("PERMISSION_DENIED" if isinstance(exc, PermissionError) else "READ_FAILED")
                walker = (os.walk(base, topdown=True, followlinks=False, onerror=walk_error)
                          if recursive else [(str(base), [], os.listdir(base))])
                for folder, dirs, names in walker:
                    visits += 1
                    if self.over_budget():
                        return stop("BUDGET_EXHAUSTED")
                    if visits > visit_budget:
                        return stop("ENUMERATION_LIMIT")
                    for x in dirs:
                        if (Path(folder) / x).is_symlink() and not covered(Path(folder) / x):
                            incomplete = True
                            gaps.add("SYMLINK_NOT_FOLLOWED")
                    dirs[:] = sorted(x for x in dirs if not (Path(folder) / x).is_symlink())
                    for name in sorted(names):
                        visits += 1
                        if self.over_budget():
                            return stop("BUDGET_EXHAUSTED")
                        if visits > visit_budget:
                            return stop("ENUMERATION_LIMIT")
                        path = Path(folder) / name
                        if path.is_symlink():
                            if extensions is None or path.suffix.lower() in extensions:
                                resolved = None if covered(path) else root_controlled_target(path)
                                if resolved is not None and len(out) < limit:
                                    out.append(resolved)
                                elif not covered(path):
                                    incomplete = True
                                    gaps.add("SYMLINK_NOT_FOLLOWED")
                            continue
                        if not path.is_file():
                            continue
                        if extensions is None or path.suffix.lower() in extensions:
                            if len(out) >= limit:
                                return stop("ENUMERATION_LIMIT")
                            out.append(path)
            except PermissionError:
                incomplete = True
                gaps.add("PERMISSION_DENIED")
            except OSError:
                incomplete = True
                gaps.add("READ_FAILED")
        return out, incomplete

    def _package_db_gap(self, manager: str, reason: str, omitted: int = 1) -> None:
        if reason not in INCOMPLETE_CODES:
            raise ValueError("Package database failure must be an incompleteness code")
        if not hasattr(self, "_package_db_gaps"):
            self._package_db_gaps = {}
        self._package_db_gaps.setdefault(manager, Counter())[reason] += omitted

    def _dpkg_md5(self, path: Path) -> str | None:
        """md5 recorded by dpkg for an installed file, from a lazily built index."""
        if self._dpkg_index is None:
            index: dict[str, str] = {}
            total = 0
            try:
                lists = sorted(self.sys("/var/lib/dpkg/info").glob("*.md5sums"))
            except OSError:
                self._package_db_gap("dpkg", "READ_FAILED")
                lists = []
            if len(lists) > DPKG_DB_MAX_RECORDS:
                self._package_db_gap("dpkg", "ENUMERATION_LIMIT", len(lists) - DPKG_DB_MAX_RECORDS)
            for offset, md5file in enumerate(lists[:DPKG_DB_MAX_RECORDS]):
                raw, read_status = safe_read(md5file, 4 * 1024 * 1024)
                if raw is None:
                    self._package_db_gap("dpkg", "INPUT_TRUNCATED" if read_status == "TOO_LARGE" else "READ_FAILED")
                    continue
                total += len(raw)
                if total > DPKG_DB_MAX_BYTES:
                    self._package_db_gap("dpkg", "ENUMERATION_LIMIT", len(lists) - offset)
                    break
                for line in raw.decode("utf-8", "replace").splitlines():
                    digest, _, rel = line.partition("  ")
                    if len(digest) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", digest) and rel:
                        index["/" + rel] = digest
                    elif line.strip():
                        self._package_db_gap("dpkg", "MALFORMED_INPUT")
            # Conffiles (/etc/...) are not in *.md5sums; dpkg records them in status.
            raw, read_status = safe_read(self.sys("/var/lib/dpkg/status"), 8 * 1024 * 1024)
            if raw is None:
                self._package_db_gap("dpkg", "INPUT_TRUNCATED" if read_status == "TOO_LARGE" else "READ_FAILED")
            if raw is not None:
                for m in re.finditer(r"^ (/\S+) ([0-9a-f]{32})(?: obsolete)?$", raw.decode("utf-8", "replace"), re.M):
                    index.setdefault(m.group(1), m.group(2))
            self._dpkg_index = index
        return self._dpkg_index.get(self.image_path(path))

    def _read_mtree(self, path: Path) -> bytes | None:
        """Decompress one pacman mtree with bounds on both sides of gzip."""
        raw, _ = safe_read(path, MTREE_MAX_COMPRESSED)
        if raw is None:
            return None
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
                data = handle.read(MTREE_MAX_DECOMPRESSED + 1)
        except (OSError, EOFError, zlib_error):
            return None
        return None if len(data) > MTREE_MAX_DECOMPRESSED else data

    def _pacman_records(self) -> dict[str, tuple[str, str]]:
        """path -> (algorithm, digest) from every local package's mtree (lazy, bounded)."""
        if self._pacman_index is None:
            index: dict[str, tuple[str, str]] = {}
            local = self.sys("/var/lib/pacman/local")
            try:
                folders = sorted(p for p in local.iterdir() if p.is_dir() and not p.is_symlink())
            except OSError:
                self._package_db_gap("pacman", "READ_FAILED")
                folders = []
            total = 0
            if len(folders) > PACKAGE_DB_MAX_RECORDS:
                self._package_db_gap("pacman", "ENUMERATION_LIMIT", len(folders) - PACKAGE_DB_MAX_RECORDS)
            for offset, folder in enumerate(folders[:PACKAGE_DB_MAX_RECORDS]):
                data = self._read_mtree(folder / "mtree")
                if data is None:
                    self._package_db_gap("pacman", "PARSE_UNSUPPORTED")
                    continue
                total += len(data)
                if total > PACKAGE_DB_MAX_BYTES:
                    self._package_db_gap("pacman", "ENUMERATION_LIMIT", len(folders) - offset)
                    break
                entries, parsed = pk.parse_pacman_mtree(data)
                if parsed.get("malformed", 0):
                    self._package_db_gap("pacman", "MALFORMED_INPUT", parsed["malformed"])
                for rel, attrs in entries.items():
                    if attrs.get("type") == "file" and rel not in pk.PACMAN_METADATA_ENTRIES:
                        if "sha256" in attrs:
                            index[rel] = ("sha256", attrs["sha256"])
                        elif "md5" in attrs:
                            index[rel] = ("md5", attrs["md5"])
            self._pacman_index = index
        return self._pacman_index

    def _apk_records(self) -> dict[str, tuple[str, str]]:
        """path -> (algorithm, base64 digest) from apk's installed database (lazy, bounded)."""
        if self._apk_index is None:
            index: dict[str, tuple[str, str]] = {}
            raw, _ = safe_read(self.sys("/lib/apk/db/installed"), APK_DB_MAX_BYTES)
            if raw is not None:
                db, _ = pk.parse_apk_installed(raw)
                for rel, info in db["files"].items():
                    if "sha256_b64" in info:
                        index[rel] = ("sha256", info["sha256_b64"])
                    elif "sha1_b64" in info:
                        index[rel] = ("sha1", info["sha1_b64"])
            self._apk_index = index
        return self._apk_index

    def _recorded_digest(self, path: Path) -> tuple[str, str] | None:
        """(algorithm, digest) the package database records for `path`, or None.

        dpkg records md5 (hex), pacman sha256 or md5 (hex), apk sha1 or sha256
        (base64). rpm keeps its records in a binary database that is not
        parsed here: rpm hosts verify through `rpm -Va` only.
        """
        managers = self.managers()
        if "dpkg" in managers:
            md5 = self._dpkg_md5(path)
            if md5 is not None:
                return ("md5", md5)
        image = self.image_path(path)
        if "pacman" in managers and image in self._pacman_records():
            return self._pacman_records()[image]
        if "apk" in managers and image in self._apk_records():
            return self._apk_records()[image]
        return None

    @staticmethod
    def _digest_matches(content: bytes, algorithm: str, expected: str) -> bool:
        digest = hashlib.new(algorithm, content, usedforsecurity=False)
        if "=" in expected or len(expected) not in (32, 40, 64):
            return base64.b64encode(digest.digest()).decode("ascii") == expected
        return digest.hexdigest() == expected.lower()

    def managers(self) -> list[str]:
        if not hasattr(self, "_managers"):
            self._managers = pk.detect_managers(self.root)
        return self._managers

    def package_attested(self, path: Path, content: bytes) -> bool:
        """Root-owned, not group/world-writable, content equal to the package record.

        A recorded digest (dpkg md5, pacman sha256/md5, apk sha1/sha256)
        detects accidental or unprivileged tampering only; an adversary with
        root can rewrite both file and record. Callers state this as a trust
        assumption, never as verification of safety. rpm hosts: never attested.
        """
        try:
            for part in (path, *path.parents):
                meta = part.lstat()
                if meta.st_uid != 0 or meta.st_mode & 0o022:
                    return False
        except OSError:
            return False
        recorded = self._recorded_digest(path)
        return recorded is not None and self._digest_matches(content, *recorded)

    def _attested_program(self, name: str) -> Path | None:
        """The packaged executable `name` resolves to, if its content matches the package record.

        Relative names are looked up in the fixed system directories only (never
        $PATH, never /usr/local); relay programs (cat, sed, sh, …) never qualify,
        because their output is their input.
        """
        # Never alias ./prog, ../prog, or path/prog to /usr/bin/prog.
        # A relative path is an execution target, not a PATH lookup name.
        if not name or ("/" in name and not name.startswith("/")):
            return None
        canonical = PurePosixPath(name)
        if name.startswith("/") and (str(canonical) != name or str(canonical.parent) not in PROGRAM_DIRS):
            return None
        base = canonical.name
        if not base or base not in ATTESTABLE_GENERATORS or base in RELAY_PROGRAMS:
            return None
        candidates = [self.sys(name)] if name.startswith("/") else [self.sys(d) / base for d in PROGRAM_DIRS]
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            content, _ = safe_read(path, 8 * 1024 * 1024)
            if content is not None and self.package_attested(path, content):
                return path
            return None
        return None

    def _shell_limit(self, analysis: dict, path: Path | str, content: bytes | None, gaps: Gaps) -> None:
        """Turn analyser limitations into the right coverage code.

        A file whose only unresolved sites are `eval "$(prog …)"` with every
        `prog` package-attested is a stated trust assumption (scope limit), not
        an incomplete inspection: this is what a stock shell start-up looks like
        (`dircolors`, `lesspipe`, prompt and shell hooks). Anything else stays
        PARSE_UNSUPPORTED.
        """
        limitations = analysis["limitations"]
        if not limitations:
            return
        if isinstance(path, Path) and content is not None and self.package_attested(path, content):
            gaps.add("PACKAGE_ATTESTED_NOT_PARSED")
            return
        programs = analysis.get("qualified_eval_sites", [])
        if (limitations == ["EXPANSION_NOT_RESOLVED"] and programs
                and analysis.get("unresolved_non_eval_sites") == 0
                and analysis.get("unresolved_expansions") == len(programs)
                and all(self._attested_program(p) is not None for p in programs)):
            gaps.add("EVAL_OF_ATTESTED_PROGRAM_OUTPUT")
            self.stats.setdefault("evaluated_attested_programs", []).append({
                "source_ref": self.source(path), "programs": sorted(set(programs))})
            return
        gaps.add("PARSE_UNSUPPORTED")
        self.stats.setdefault("shell_analysis_limits", []).append({
            "source_ref": self.source(path), "limitations": limitations})

    def _command_text_review(self, text: str, path: Path, content: bytes, gaps: Gaps) -> list[str]:
        """Static shell analysis of scheduler/autostart command text with explicit limits."""
        analysis = analyze_shell(text)
        self._shell_limit(analysis, path, content, gaps)
        return analysis["patterns"]

    def _resolve_sourced(self, target: str) -> Path | None:
        """Resolve a literal source/. operand: ~/, $HOME/ and ${HOME}/ forms only."""
        for prefix in ("~/", "\x00VAR:HOME\x00/"):
            if target.startswith(prefix):
                suffix = target[len(prefix):].lstrip("/")
                components = PurePosixPath(suffix).parts
                if not components or any(part in (".", "..") for part in components):
                    return None
                return self.home.joinpath(*components)
        if "\x00" in target or not target.startswith("/"):
            return None
        # An absolute operand names a file of the inspected system: resolve it
        # under the scan root (identical to the literal path on the live host).
        return self.sys(target)

    def persistence(self) -> None:
        units = [self.sys("/etc/systemd/system"), self.sys("/etc/systemd/user"),
                 self.home / ".config/systemd/user"]
        # Package-supplied units also participate in persistence, and can be
        # modified by privileged attackers. Do not mistake /etc-only for full
        # systemd coverage. /lib is usually a symlink to /usr/lib on Ubuntu.
        # User-manager vendor units (/usr/lib/systemd/user) are where enabled
        # per-user services resolve to; without them those links are unseen.
        for kind in ("system", "user"):
            vendor_units = self.sys("/usr/lib/systemd") / kind
            if vendor_units.is_dir() and not vendor_units.is_symlink():
                units.append(vendor_units)
            else:
                fallback = self.sys("/lib/systemd") / kind
                if fallback.is_dir() and not fallback.is_symlink():
                    units.append(fallback)
        gaps = Gaps()
        units_found, trunc = self._files(units, extensions={".service", ".timer", ".socket"}, recursive=True, limit=2600,
                                         gaps=gaps)
        count = 0
        unreadable = 0
        symlink_count = 0
        ssh_unreadable = 0
        for base in units:
            if not base.is_dir() or base.is_symlink():
                continue
            try:
                visits = 0
                for folder, dirs, names in os.walk(base, followlinks=False):
                    if self.over_budget() or visits > self.profile_config["max_file_visits"]:
                        gaps.add("BUDGET_EXHAUSTED" if self.over_budget() else "ENUMERATION_LIMIT")
                        break
                    dirs[:] = sorted(x for x in dirs if not (Path(folder) / x).is_symlink())
                    for name in sorted(names):
                        visits += 1
                        if visits > self.profile_config["max_file_visits"] or self.over_budget():
                            gaps.add("BUDGET_EXHAUSTED" if self.over_budget() else "ENUMERATION_LIMIT")
                            break
                        p = Path(folder) / name
                        if p.suffix != ".service" or not p.is_symlink():
                            continue
                        symlink_count += 1
                        try:
                            target = os.readlink(p)
                        except OSError:
                            gaps.add("READ_FAILED")
                            continue
                        if any(v in target for v in d.SUSPICIOUS_PATHS):
                            self.finding("SYSTEMD_SYMLINK_TO_TEMP", "high", "Service symlink resolves through volatile path", p,
                                         {"target_ref": d.digest(target)}, attack="T1543.002")
            except (OSError, PermissionError):
                gaps.add("READ_FAILED")
        for p in units_found:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                break
            raw, st = safe_read(p, 128 * 1024)
            if raw is None:
                unreadable += 1
                self.read_gap(p, st, gaps)
                continue
            count += 1
            self.baseline["systemd_units"].append(d.digest(str(p) + ":" + hashlib.sha256(raw).hexdigest()))
            if p.suffix == ".service":
                rules = d.suspicious_systemd(raw.decode("utf-8", "replace"))
                if rules:
                    temporal = self._mtime_near_incident(p)
                    self.finding("SUSPICIOUS_SYSTEMD_EXECUTION", "high", "Service may execute from volatile location or fetch a remote script", p,
                                 {"pattern_rules": rules, "mtime_near_incident_72h": temporal}, attack="T1543.002")
        preload = self.sys("/etc/ld.so.preload")
        loader, loader_status = safe_read(preload, 8192)
        if loader is None:
            self.read_gap(preload, loader_status, gaps)
        if loader:
            self.finding("SYSTEM_LOADER_PRELOAD", "medium", "Dynamic loader system preload is configured; verify provenance", preload,
                         {"entry_count": len([l for l in loader.splitlines() if l.strip()])}, kind="INDICATOR", attack="T1574.006")
        cronfiles, crontrunc = self._files(
            [self.sys("/etc/cron.d"), self.sys("/etc/cron.daily"), self.sys("/etc/cron.hourly"), self.sys("/etc/cron.weekly"),
             self.sys("/etc/cron.monthly"), self.home / ".config/cron"], recursive=False, limit=500, gaps=gaps,
            follow_root_links=True)
        for p in cronfiles:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                break
            raw, st = safe_read(p, 64 * 1024)
            if raw is None:
                unreadable += 1
                self.read_gap(p, st, gaps)
                continue
            self.baseline["cron_entry_hashes"].append(d.digest(str(p) + ":" + hashlib.sha256(raw).hexdigest()))
            flags = self._command_text_review(cron_commands(raw.decode("utf-8", "replace"), system=p.parent == self.sys("/etc/cron.d")),
                                              p, raw, gaps)
            if flags:
                self.finding("SUSPICIOUS_CRON_EXECUTION", "high", "Cron includes risky command pattern", p,
                             {"patterns": flags}, attack="T1053.003")
        cr = self._user_crontab()
        if cr["status"] == "COMPLETED":
            cron = cr["stdout"]
            self.baseline["cron_entry_hashes"].extend(d.digest(line) for line in cron.splitlines() if line.strip() and not line.lstrip().startswith("#"))
            analysis = analyze_shell(cron_commands(cron))
            flags = analysis["patterns"]
            self._shell_limit(analysis, "crontab://target-user", None, gaps)
            if flags:
                self.finding("SUSPICIOUS_USER_CRONTAB", "high", "User cron includes command execution concerns", "crontab://target-user", {"patterns": flags}, attack="T1053.003")
        for p in (self.home / ".ssh/authorized_keys", self.home / ".ssh/authorized_keys2"):
            raw, st = safe_read(p, 128 * 1024)
            if raw is None and st not in ("ABSENT",):
                ssh_unreadable += 1
                self.read_gap(p, st, gaps)
            if raw:
                fingerprints = []
                for line in raw.decode("utf-8", "replace").splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    fingerprints.append(d.digest(line, 32))
                self.baseline["ssh_key_fingerprints"].extend(fingerprints)
                info = p.stat()
                if stat.S_IMODE(info.st_mode) & 0o077:
                    self.finding("SSH_AUTHORIZED_KEYS_PERMISSIONS", "low", "SSH authorized keys permissions are broad", p,
                                 {"mode": oct(stat.S_IMODE(info.st_mode)), "count": len(fingerprints)}, kind="HARDENING")
        queue = [self.home / ".bashrc", self.home / ".profile", self.home / ".bash_profile", self.home / ".zshrc",
                 self.home / ".bash_login", self.home / ".bash_logout", self.home / ".zprofile",
                 self.home / ".config/fish/config.fish"]
        seen: set[str] = set()
        while queue:
            p = queue.pop(0)
            if p.as_posix() in seen or len(seen) >= MAX_SHELL_FILES:
                if p.as_posix() not in seen:
                    gaps.add("ENUMERATION_LIMIT")
                continue
            seen.add(p.as_posix())
            raw, st = safe_read(p, 128 * 1024)
            if raw is None and st != "ABSENT":
                unreadable += 1
                self.read_gap(p, st, gaps)
            if raw:
                analysis = analyze_shell(raw.decode("utf-8", "replace"))
                for target in analysis.get("sourced", []):
                    resolved = self._resolve_sourced(target)
                    if resolved is None:
                        gaps.add("PARSE_UNSUPPORTED")
                        self.stats.setdefault("shell_analysis_limits", []).append({
                            "source_ref": self.source(p), "limitations": ["SOURCED_PATH_NOT_RESOLVED"]})
                    elif resolved.as_posix().startswith(self.home.as_posix().rstrip("/") + "/"):
                        queue.append(resolved)  # user-controlled: analyse it too
                    else:
                        content, rst = safe_read(resolved, 512 * 1024)
                        if content is not None and not self.package_attested(resolved, content):
                            queue.append(resolved)
                        elif content is None and rst != "ABSENT":
                            self.read_gap(resolved, rst, gaps)
                rules = analysis["patterns"]
                self._shell_limit(analysis, p, None, gaps)   # start-up files are the user's: never package-attested here
                if rules:
                    self.finding("SUSPICIOUS_SHELL_INIT", "medium", "Shell initialization contains literal risky command syntax; not proof of execution", p,
                                 {"patterns": rules, "file_name": p.name, "locations": analysis["matches"],
                                  "limitations": analysis["limitations"]}, attack="T1546.004")
        autostart, a_trunc = self._files([self.home / ".config/autostart", self.sys("/etc/xdg/autostart")],
                                         extensions={".desktop"}, limit=300, gaps=gaps)
        for p in autostart:
            raw, st = safe_read(p, 64 * 1024)
            if raw is None:
                unreadable += 1
                self.read_gap(p, st, gaps)
            if raw:
                rules = self._command_text_review(desktop_commands(raw.decode("utf-8", "replace")), p, raw, gaps)
                if rules:
                    self.finding("SUSPICIOUS_AUTOSTART", "medium", "Autostart entry references risky execution", p,
                                 {"patterns": rules}, attack="T1547.013")
        s_trunc = False
        if self.scope == "system":
            sudoers, s_trunc = self._files([self.sys("/etc/sudoers.d")], limit=300, gaps=gaps)
            for p in sudoers:
                raw, st = safe_read(p, 32 * 1024)
                if raw is None:
                    unreadable += 1
                    self.read_gap(p, st, gaps)
                if raw and b"NOPASSWD:" in raw:
                    self.finding("SUDO_NOPASSWD_RULE", "low", "Passwordless sudo policy present; authorization must be reviewed", p,
                                 {"configuration_present": True}, kind="HARDENING")
        self.stats["persistence"] = {"systemd_units_read": count, "cron_files_found": len(cronfiles),
                                     "autostart_found": len(autostart), "authorized_keys_count": len(self.baseline["ssh_key_fingerprints"]),
                                     "unreadable": unreadable, "ssh_unreadable": ssh_unreadable,
                                     "systemd_symlink_count": symlink_count}
        cron_absent = cr["status"] == "FAILED" and "no crontab for" in cr.get("stderr", "").lower()
        if not cron_absent:
            self.command_gap(cr, gaps)
        if self.scope == "user":
            gaps.add("REQUIRES_SYSTEM_SCOPE")  # /etc/sudoers.d is root-only
        self.conclude("persistence",
                      "Selected systemd/custom units (including symlink metadata), cron, SSH public-key hashes, shell and XDG autoruns; shell analysis is a lexical subset, not full Bash evaluation",
                      gaps, len(units_found) + len(cronfiles) + len(autostart))

    def _user_crontab(self) -> dict:
        """`crontab -l` on a live host; the spool file itself on an offline image."""
        if not self.offline:
            return self.command("crontab", ["-l", "-u", self.target_user] if self.scope == "system" else ["-l"],
                                timeout=6, limit=64*1024)
        for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
            path = self.sys(spool) / self.target_user
            raw, status = safe_read(path, 64 * 1024)
            if raw is not None:
                return {"status": "COMPLETED", "stdout": raw.decode("utf-8", "replace"), "stderr": "", "exit": 0,
                        "elapsed_ms": 0, "truncated": False, "error": "", "residual_killed": False}
            if status not in ("ABSENT",):
                return {"status": "FAILED", "stdout": "", "stderr": status, "exit": 1, "elapsed_ms": 0,
                        "truncated": False, "error": status, "residual_killed": False}
        return {"status": "FAILED", "stdout": "", "stderr": f"no crontab for {self.target_user}", "exit": 1,
                "elapsed_ms": 0, "truncated": False, "error": "", "residual_killed": False}

    def _chromium_extension_settings(self, profile: Path, gaps: Gaps) -> dict[str, dict] | None:
        """extensions.settings from Preferences + Secure Preferences, or None if unreadable."""
        merged: dict[str, dict] = {}
        readable = False
        for name in ("Preferences", "Secure Preferences"):
            raw, st = safe_read(profile / name, MAX_PREFERENCES_BYTES)
            if raw is None:
                self.read_gap(profile / name, st, gaps)
                continue
            try:
                doc = json.loads(raw)
            except (ValueError, RecursionError):
                gaps.add("MALFORMED_INPUT")
                continue
            readable = True
            settings = doc.get("extensions", {}).get("settings", {}) if isinstance(doc, dict) else {}
            if isinstance(settings, dict):
                for ext_id, value in settings.items():
                    if isinstance(value, dict):
                        merged.setdefault(ext_id, {}).update(value)
        return merged if readable else None

    @staticmethod
    def _chromium_state(setting: dict | None) -> dict:
        """Enabled/granted state from browser preferences; UNKNOWN when not stated."""
        if setting is None:
            return {"enabled": "UNKNOWN", "granted": "UNKNOWN", "withheld_host_permissions": "UNKNOWN",
                    "install_location": "UNKNOWN", "from_webstore": "UNKNOWN"}
        reasons = setting.get("disable_reasons")
        if isinstance(reasons, list):
            enabled: bool | str = not reasons
        elif isinstance(reasons, int):
            enabled = reasons == 0
        elif setting.get("state") in (0, 1):
            enabled = setting["state"] == 1
        else:
            enabled = "UNKNOWN"
        granted_raw = setting.get("granted_permissions")
        granted: dict | str = "UNKNOWN"
        if isinstance(granted_raw, dict):
            granted = {k: sorted(x for x in granted_raw.get(k, []) if isinstance(x, str))[:60]
                       for k in ("api", "explicit_host", "scriptable_host") if isinstance(granted_raw.get(k, []), list)}
        withheld = setting.get("withholding_permissions")
        location = setting.get("location")
        return {"enabled": enabled, "granted": granted,
                "withheld_host_permissions": withheld if isinstance(withheld, bool) else "UNKNOWN",
                "install_location": CHROMIUM_LOCATIONS.get(location, "UNKNOWN")
                if isinstance(location, int) and not isinstance(location, bool) else "UNKNOWN",
                "from_webstore": setting.get("from_webstore") if isinstance(setting.get("from_webstore"), bool) else "UNKNOWN"}

    def _extension_name(self, manifest: dict, version_dir: Path) -> dict:
        """Display name; __MSG_x__ placeholders resolved from the default locale only.

        A name is a label chosen by the extension author, not publisher identity.
        """
        name = manifest.get("name")
        if not isinstance(name, str):
            return {"name": "UNKNOWN"}
        name = name[:120]
        match = re.fullmatch(r"__MSG_(\w+)__", name)
        if not match:
            return {"name": name}
        locale = manifest.get("default_locale")
        if isinstance(locale, str) and re.fullmatch(r"[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8})?", locale):
            raw, _ = safe_read(version_dir / "_locales" / locale / "messages.json", d.MAX_JSON_BYTES)
            try:
                messages = json.loads(raw) if raw else {}
            except (ValueError, RecursionError):
                messages = {}
            if isinstance(messages, dict):
                for key, entry in messages.items():
                    if key.lower() == match.group(1).lower() and isinstance(entry, dict) and isinstance(entry.get("message"), str):
                        return {"name": entry["message"][:120], "name_source": "default_locale"}
        return {"name": name, "name_source": "UNRESOLVED_PLACEHOLDER"}

    @staticmethod
    def _content_script_matches(manifest: dict) -> list[str]:
        out: set[str] = set()
        scripts = manifest.get("content_scripts", [])
        for cs in scripts if isinstance(scripts, list) else []:
            matches = cs.get("matches", []) if isinstance(cs, dict) else []
            if isinstance(matches, list):
                out.update(m[:200] for m in matches if isinstance(m, str))
        return sorted(out)[:40]

    def _scan_chromium(self, name: str, base: Path, gaps: Gaps | None = None) -> tuple[int, int, bool]:
        gaps = gaps if gaps is not None else Gaps()
        if base.is_symlink():
            gaps.add("SYMLINK_NOT_FOLLOWED")
            return 0, 0, True
        if not base.is_dir():
            return 0, 0, False
        ext_count, profile_count, truncated = 0, 0, False
        profiles = []
        try:
            for p in base.iterdir():
                if not p.is_dir() or p.is_symlink():
                    continue
                # Custom-named profiles exist; a profile is a folder with browser
                # preferences or extensions, not only Default / "Profile N".
                if (p.name == "Default" or p.name.startswith("Profile ")
                        or (p / "Preferences").is_file() or (p / "Extensions").is_dir()):
                    profiles.append(p)
        except (PermissionError, OSError):
            gaps.add("PERMISSION_DENIED")
            return 0, 0, True
        if len(profiles) > 30:
            gaps.add("ENUMERATION_LIMIT")
            truncated = True
        for prof in sorted(profiles, key=lambda p: p.name)[:30]:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                truncated = True
                break
            profile_count += 1
            exts = prof / "Extensions"
            if exts.is_symlink():
                gaps.add("SYMLINK_NOT_FOLLOWED")
                truncated = True
                continue
            if not exts.is_dir():
                continue
            settings = self._chromium_extension_settings(prof, gaps) if (prof / "Preferences").exists() else None
            profile_ref = self.source(prof)
            try:
                ext_ids = sorted(exts.iterdir(), key=lambda p: p.name)[:201]
            except (OSError, PermissionError):
                gaps.add("PERMISSION_DENIED")
                truncated = True
                continue
            if len(ext_ids) > 200:
                gaps.add("ENUMERATION_LIMIT")
                truncated = True
            for extdir in ext_ids[:200]:
                if self.over_budget():
                    gaps.add("BUDGET_EXHAUSTED")
                    truncated = True
                    break
                if extdir.name == "Temp":
                    continue  # Chromium's install staging folder, not an extension
                if extdir.is_symlink():
                    gaps.add("SYMLINK_NOT_FOLLOWED")
                    truncated = True
                    continue
                if not extdir.is_dir():
                    gaps.add("MALFORMED_INPUT")
                    truncated = True
                    continue
                try:
                    versions = sorted((x for x in extdir.iterdir() if x.is_dir() and not x.is_symlink()),
                                      key=_extension_version_key, reverse=True)
                except (OSError, PermissionError):
                    gaps.add("PERMISSION_DENIED")
                    truncated = True
                    continue
                if not versions:
                    gaps.add("MALFORMED_INPUT")
                    truncated = True
                for version in versions[:1]:
                    manifest_path = version / "manifest.json"
                    raw, st = safe_read(manifest_path, d.MAX_JSON_BYTES)
                    if raw is None:
                        # A discovered version directory with no readable
                        # manifest cannot be asserted to have been inspected.
                        if st == "ABSENT":
                            gaps.add("MALFORMED_INPUT")  # version folder without a manifest
                        else:
                            self.read_gap(manifest_path, st, gaps)
                        truncated = True
                        continue
                    try:
                        manifest = d.safe_json_parse(raw)
                        r = d.extension_assessment(manifest)
                    except (ValueError, TypeError, json.JSONDecodeError):
                        self.finding("INVALID_EXTENSION_MANIFEST", "low", "Unreadable or malformed extension manifest", manifest_path,
                                     {"browser": name}, kind="EXPOSURE")
                        continue
                    ext_count += 1
                    ext_id = d.digest(extdir.name, 24)
                    self.baseline["browser_extensions"].append(f"{name}:{ext_id}:{d.digest(raw)}")
                    state = self._chromium_state(settings.get(extdir.name) if settings is not None else None)
                    if r["risk_flag"] and state["enabled"] is not False:
                        identity = {"extension_id": extdir.name[:64], **self._extension_name(manifest, version),
                                    "version": str(manifest.get("version", "UNKNOWN"))[:40],
                                    "profile_ref": profile_ref, **state,
                                    "declared_permissions": sorted(x for x in manifest.get("permissions", []) if isinstance(x, str))[:60]
                                    if isinstance(manifest.get("permissions"), list) else [],
                                    "declared_host_permissions": sorted(x for x in manifest.get("host_permissions", []) if isinstance(x, str))[:60]
                                    if isinstance(manifest.get("host_permissions"), list) else [],
                                    "optional_sensitive_permissions": r["optional_sensitive_permissions"],
                                    "content_script_matches": self._content_script_matches(manifest),
                                    "native_hosts_allowing": sorted(self.native_hosts_by_extension.get(extdir.name, []))}
                        self.finding("POWERFUL_BROWSER_EXTENSION", "medium",
                                     "Browser extension declares capabilities to read or alter web content or browser state; declaration is not observed behaviour",
                                     manifest_path,
                                     {"browser": name, "extension_ref": ext_id,
                                      "sensitive_permissions": r["sensitive_permissions"],
                                      "broad_host_access": r["broad_host_access"],
                                      "host_scope": r["host_scope"],
                                      "content_script_scope": r["content_script_scope"],
                                      "extension": identity},
                                     kind="EXPOSURE", attack="T1176.001")
        return ext_count, profile_count, truncated

    def _scan_firefox(self, base: Path | None = None, label: str = "firefox", gaps: Gaps | None = None) -> tuple[int, bool]:
        gaps = gaps if gaps is not None else Gaps()
        base = base or (self.home / ".mozilla/firefox")
        if base.is_symlink():
            gaps.add("SYMLINK_NOT_FOLLOWED")
            return 0, True
        if not base.is_dir():
            return 0, False
        profiles = []
        try:
            entries = list(base.iterdir())
            profiles = [x for x in entries if x.is_dir() and not x.is_symlink()
                        and (".default" in x.name or ".release" in x.name or (x / "extensions.json").is_file())]
            skipped_links = any(x.is_symlink() and (".default" in x.name or ".release" in x.name) for x in entries)
        except (OSError, PermissionError):
            gaps.add("PERMISSION_DENIED")
            return 0, True
        count = 0
        truncated = len(profiles) > 30 or skipped_links
        if len(profiles) > 30:
            gaps.add("ENUMERATION_LIMIT")
        if skipped_links:
            gaps.add("SYMLINK_NOT_FOLLOWED")
        for prof in sorted(profiles, key=lambda p: p.name)[:30]:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                truncated = True
                break
            path = prof / "extensions.json"
            raw, st = safe_read(path, d.MAX_JSON_BYTES)
            if raw is None:
                # Missing, unreadable or oversized profile metadata means
                # extension grants were not independently assessed.
                if st == "ABSENT":
                    gaps.add("READ_FAILED")
                else:
                    self.read_gap(path, st, gaps)
                truncated = True
                continue
            try:
                obj = d.safe_json_parse(raw)
                addons = obj.get("addons", []) if isinstance(obj, dict) else []
                if not isinstance(addons, list):
                    gaps.add("MALFORMED_INPUT")
                    truncated = True
                    continue
            except (ValueError, TypeError, json.JSONDecodeError):
                gaps.add("MALFORMED_INPUT")
                truncated = True
                continue
            if len(addons) > 200:
                gaps.add("ENUMERATION_LIMIT")
                truncated = True
            profile_ref = self.source(prof)
            for addon in addons[:200]:
                if not isinstance(addon, dict):
                    gaps.add("MALFORMED_INPUT")
                    truncated = True
                    continue
                if addon.get("type") not in ("extension", None):
                    continue
                count += 1
                raw_id = str(addon.get("id", "unknown"))
                aid = d.digest(raw_id, 24)
                self.baseline["browser_extensions"].append(f"{label}:{aid}:{d.digest(json.dumps(addon, sort_keys=True))}")
                perms = addon.get("userPermissions", {})
                if isinstance(perms, dict):
                    p = [x for x in perms.get("permissions", []) if isinstance(x, str)] if isinstance(perms.get("permissions", []), list) else []
                    o = [x for x in perms.get("origins", []) if isinstance(x, str)] if isinstance(perms.get("origins", []), list) else []
                    review = d.extension_assessment({"permissions": p, "host_permissions": o})
                    disabled = (addon.get("active", True) is False or addon.get("userDisabled") is True
                                or addon.get("appDisabled") is True)
                    # Disabled add-ons are inventoried but not presented as active exposure.
                    if review["risk_flag"] and not disabled:
                        optional = addon.get("optionalPermissions", {})
                        locale = addon.get("defaultLocale", {})
                        signed = addon.get("signedState")
                        identity = {
                            "extension_id": raw_id[:120],
                            "name": str(locale.get("name"))[:120] if isinstance(locale, dict) and locale.get("name") else "UNKNOWN",
                            "version": str(addon.get("version", "UNKNOWN"))[:40],
                            "profile_ref": profile_ref,
                            "enabled": True if addon.get("active") is True else "UNKNOWN",
                            # Firefox records accepted required permissions in userPermissions.
                            "granted": {"api": sorted(p)[:60], "origins": sorted(o)[:60]},
                            "optional_permissions": sorted(x for x in optional.get("permissions", []) if isinstance(x, str))[:60]
                            if isinstance(optional, dict) and isinstance(optional.get("permissions"), list) else [],
                            "install_location": str(addon.get("location", "UNKNOWN"))[:40],
                            "signed_state": FIREFOX_SIGNED_STATES.get(signed, "UNKNOWN")
                            if isinstance(signed, int) and not isinstance(signed, bool) else "UNKNOWN",
                            "native_hosts_allowing": sorted(self.native_hosts_by_extension.get(raw_id, [])),
                        }
                        self.finding("POWERFUL_FIREFOX_EXTENSION", "medium",
                                     "Firefox extension holds powerful host/API permissions; permission is capability, not observed behaviour",
                                     path,
                                     {"browser": label, "extension_ref": aid,
                                      "sensitive_permissions": review["sensitive_permissions"],
                                      "broad_host_access": review["broad_host_access"],
                                      "host_scope": review["host_scope"],
                                      "extension": identity},
                                     kind="EXPOSURE", attack="T1176.001")
        return count, truncated

    def _native_hosts(self, gaps: Gaps) -> int:
        """Inspect native-messaging manifests; link hosts to the extensions they admit."""
        native_dirs = [
            self.home / ".config/google-chrome/NativeMessagingHosts",
            self.home / ".config/chromium/NativeMessagingHosts",
            self.home / ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
            self.home / ".config/microsoft-edge/NativeMessagingHosts",
            self.home / ".mozilla/native-messaging-hosts",
            self.home / "snap/firefox/common/.mozilla/native-messaging-hosts",
            self.home / ".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts",
            self.sys("/etc/opt/chrome/native-messaging-hosts"),
            self.sys("/etc/chromium/native-messaging-hosts"),
            self.sys("/usr/lib/mozilla/native-messaging-hosts"),
        ]
        natives, _ = self._files(native_dirs, extensions={".json"}, limit=250, gaps=gaps, follow_root_links=True)
        # Paths written inside manifests are the inspected system's own names.
        home_prefix = self.image_path(self.home).rstrip("/") + "/"
        for path in natives:
            raw, st = safe_read(path, d.MAX_JSON_BYTES)
            if raw is None:
                self.read_gap(path, st, gaps)
                continue
            try:
                manifest = d.safe_json_parse(raw)
                if not isinstance(manifest, dict):
                    gaps.add("MALFORMED_INPUT")
                    continue
            except (ValueError, json.JSONDecodeError):
                gaps.add("MALFORMED_INPUT")
                continue
            self.baseline["native_hosts"].append(d.digest(str(path) + ":" + d.digest(raw)))
            host_name = str(manifest.get("name", "UNKNOWN"))[:120]
            allowed: list[str] = []
            for key in ("allowed_origins", "allowed_extensions"):
                values = manifest.get(key, [])
                for v in values if isinstance(values, list) else []:
                    if isinstance(v, str):
                        m = re.fullmatch(r"chrome-extension://([a-p]{32})/?", v)
                        allowed.append(m.group(1) if m else v[:120])
            for ext in allowed:
                self.native_hosts_by_extension.setdefault(ext, set()).add(host_name)
            host_path = str(manifest.get("path", ""))
            if host_path and (d.is_temp_executable(host_path) or host_path.startswith(home_prefix)):
                self.finding("NATIVE_HOST_OUTSIDE_STANDARD_PATH", "medium",
                             "Native messaging host executable lives in a user-writable or temporary location; location alone is not intrusion",
                             path,
                             {"host_path_id": d.digest(host_path), "host_name": host_name,
                              "manifest_owner": NATIVE_HOST_OWNERS.get(path.parent.parent.name, path.parent.parent.name[:40]),
                              "allowed_extensions": sorted(set(allowed))[:40],
                              "manifest_location": "user" if self.image_path(path).startswith(home_prefix) else "system",
                              "executable": self._file_identity(self.sys(host_path)),
                              "host_path_ref": self.source(host_path)},
                             kind="EXPOSURE", attack="T1176.001")
        return len(natives)

    @staticmethod
    def _file_identity(path: Path) -> dict:
        """lstat metadata and bounded hash of a referenced executable (never executed)."""
        try:
            info = path.lstat()
        except FileNotFoundError:
            return {"status": "ABSENT"}
        except OSError:
            return {"status": "UNREADABLE"}
        meta: dict[str, Any] = {"status": "PRESENT", "is_symlink": stat.S_ISLNK(info.st_mode),
                                "owner_uid": info.st_uid, "mode_oct": oct(stat.S_IMODE(info.st_mode)),
                                "size": info.st_size,
                                "executable_bits": bool(info.st_mode & 0o111)}
        if stat.S_ISREG(info.st_mode):
            raw, st = safe_read(path, min(MAX_EXE_HASH_BYTES, 8 * 1024 * 1024))
            meta["sha256"] = hashlib.sha256(raw).hexdigest() if raw is not None else f"NOT_HASHED_{st}"
        return meta

    def browsers(self) -> None:
        gaps = Gaps()
        self.native_hosts_by_extension = {}
        native_count = self._native_hosts(gaps)
        chromium = {
            "google-chrome": self.home / ".config/google-chrome",
            "brave": self.home / ".config/BraveSoftware/Brave-Browser",
            "chromium": self.home / ".config/chromium",
            "microsoft-edge": self.home / ".config/microsoft-edge",
            "chromium-snap": self.home / "snap/chromium/common/chromium",
            "chromium-flatpak": self.home / ".var/app/org.chromium.Chromium/config/chromium",
            "brave-flatpak": self.home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
            "chrome-flatpak": self.home / ".var/app/com.google.Chrome/config/google-chrome",
            "edge-flatpak": self.home / ".var/app/com.microsoft.Edge/config/microsoft-edge",
        }
        stats = {}
        for name, path in chromium.items():
            ext, profiles, truncated = self._scan_chromium(name, path, gaps)
            stats[name] = {"profiles": profiles, "extensions": ext, "profile_scan_limited": truncated}
        firefox_paths = {
            "firefox": self.home / ".mozilla/firefox",
            "firefox-snap": self.home / "snap/firefox/common/.mozilla/firefox",
            "firefox-flatpak": self.home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
        }
        for label, base in firefox_paths.items():
            count, trunc = self._scan_firefox(base, label, gaps)
            stats[label] = {"extensions": count, "profile_scan_limited": trunc}
        policies = [self.sys("/etc/opt/chrome/policies/managed"), self.sys("/etc/chromium/policies/managed"),
                    self.sys("/etc/brave/policies/managed"), self.sys("/etc/opt/edge/policies/managed"),
                    self.sys("/etc/firefox/policies"), self.sys("/usr/lib/firefox/distribution")]
        policy_files, _ = self._files(policies, extensions={".json"}, limit=200, gaps=gaps)
        for p in policy_files:
            raw, st = safe_read(p, d.MAX_JSON_BYTES)
            if raw:
                try:
                    obj = d.safe_json_parse(raw)
                except (ValueError, json.JSONDecodeError):
                    gaps.add("MALFORMED_INPUT")
                    continue
                if isinstance(obj, dict):
                    forced = any(k in obj for k in ("ExtensionInstallForcelist", "ExtensionInstallSources", "ExtensionSettings", "DisableAppUpdate"))
                    if forced:
                        self.finding("BROWSER_ENTERPRISE_POLICY", "low", "Browser management policy requires authorization review", p,
                                     {"force_install_policy_detected": forced}, kind="EXPOSURE")
            else:
                self.read_gap(p, st, gaps)
        self.stats["browsers"] = {"profiles": stats, "native_hosts_count": native_count,
                                   "enterprise_policy_files_count": len(policy_files)}
        self.conclude("browsers",
                      "Static extension manifests and browser preference state, Firefox add-on metadata, native messaging hosts, managed policies; no cookies/passwords/history collected",
                      gaps, sum(x.get("extensions", 0) for x in stats.values()) + native_count + len(policy_files))

    def _journal(self, match: list[str], days: int, lines: int, timeout: int) -> dict:
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S UTC")
        prefix: list[str] = []
        if self.offline:
            journal_dir = self.sys("/var/log/journal")
            # journalctl resolves its own pathname. Reject symlinks in every
            # ancestor rather than checking only the final directory.
            # The image must additionally be mounted read-only to eliminate
            # path-swap races between this preflight and journalctl.
            if (not journal_dir.is_dir() or
                    any(part.is_symlink() for part in (journal_dir, *journal_dir.parents)
                        if part != part.parent)):
                return {"status": "UNAVAILABLE", "stdout": "", "stderr": "", "exit": None, "elapsed_ms": 0,
                        "truncated": False, "error": "no journal directory in image", "residual_killed": False}
            prefix = [f"--directory={journal_dir.absolute().as_posix()}"]
        return self.command("journalctl", [*prefix, *match, "--since", since, "--lines", str(lines), "--no-pager", "--output=json",
                                           "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"],
                            timeout=timeout, limit=JOURNAL_OUTPUT_LIMIT)

    def _journal_signals(self, stdout: str) -> tuple[Counter[str], Counter[str], int, int, int]:
        counters: Counter[str] = Counter()
        within: Counter[str] = Counter()
        lines = malformed = timestamp_errors = 0
        for line in stdout.splitlines():
            try:
                item = d.safe_json_parse(line.encode(), 131_072)
                if not isinstance(item, dict):
                    continue
                msg = item.get("MESSAGE", "")
                if not isinstance(msg, str):
                    msg = ""
                lines += 1
                signals = d.detect_journal_message(msg)
                counters.update(signals)
                if self.incident_at:
                    try:
                        event_us = int(item["__REALTIME_TIMESTAMP"])
                        if event_us <= 0:
                            raise ValueError("missing or invalid journal timestamp")
                        event_time = dt.datetime.fromtimestamp(event_us / 1_000_000, tz=dt.timezone.utc)
                        hours = (event_time - self.incident_at).total_seconds() / 3600
                        if 0 <= hours <= 72:
                            within.update(signals)
                    except (ValueError, TypeError, OverflowError, KeyError):
                        timestamp_errors += 1
            except (ValueError, TypeError, json.JSONDecodeError):
                malformed += 1
        return counters, within, lines, malformed, timestamp_errors

    def auth(self) -> None:
        """Target: every auth/authpriv journal entry of the last 30 days.

        Filtering by facility keeps the target small enough to read completely;
        reading only the newest N lines of the whole journal would sample it.
        """
        gaps = Gaps()
        event_limit = self.profile_config["journal_lines"]
        r = self._journal(["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], 30, event_limit, 30)
        if r["status"] == "UNAVAILABLE":
            # No journald (Alpine, Void, Devuan, containers): classic syslog files
            # are the same target read through a different interface.
            self._auth_from_syslog_files(gaps, event_limit)
            return
        self.command_gap(r, gaps)
        if r["status"] not in ("COMPLETED", "PARTIAL"):
            self.checked("auth", "FAILED", "No usable journald data; cannot infer absence of intrusion", gaps=gaps)
            return
        counters, within, lines, malformed, timestamp_errors = self._journal_signals(r["stdout"])
        if counters["SSH_ACCEPTED"]:
            self.finding("REMOTE_AUTHENTICATION_REVIEW", "low", "SSH logins observed; compare timestamps and source against your own sessions", "journald://ssh",
                         {"ssh_accepted_count": counters["SSH_ACCEPTED"]}, kind="CONTEXT", attack="T1078")
        self.stats["auth"] = {"events_examined": lines, "event_counts": dict(counters), "malformed": malformed,
                              "invalid_incident_timestamps": timestamp_errors,
                              "window_days_max": 30, "max_event_lines": event_limit,
                              "event_counts_0_to_72h_after_incident": dict(within) if self.incident_at else None}
        if lines >= event_limit:
            gaps.add("INPUT_TRUNCATED")
        if malformed:
            gaps.add("MALFORMED_INPUT", malformed)
        if timestamp_errors:
            gaps.add("MALFORMED_INPUT", timestamp_errors)
        if lines == 0:
            gaps.add("HISTORY_UNAVAILABLE")
        if self.scope == "user" and not _in_journal_reader_group():
            gaps.add("OTHER_ACCOUNTS_NOT_VISIBLE")
        self.conclude("auth", "auth/authpriv journald entries within 30 days; no raw messages retained; absence of logging is not absence of incident",
                      gaps, lines)

    def _auth_from_syslog_files(self, gaps: Gaps, event_limit: int) -> None:
        """journald-free hosts: /var/log/auth.log, secure or messages, bounded.

        Classic syslog lines carry no year and no facility, so the 30-day
        window and the incident correlation are not computed; the whole
        retained file is the target. Unreadable files are incompleteness in
        system scope and a scope limit in user scope (log group membership).
        """
        counters: Counter[str] = Counter()
        lines = 0
        files_read: list[str] = []
        present = 0
        for name in AUTH_LOG_FILES:
            path = self.sys(name)
            try:
                if not path.is_file() or path.is_symlink():
                    continue
            except OSError:
                continue
            present += 1
            raw, status = safe_read(path, AUTH_LOG_MAX_BYTES)
            if raw is None:
                if status == "TOO_LARGE":
                    gaps.add("INPUT_TRUNCATED")
                else:
                    self.read_gap(path, status, gaps)
                continue
            files_read.append(self.image_path(path))
            for line in raw.decode("utf-8", "replace").splitlines():
                if lines >= event_limit:
                    gaps.add("INPUT_TRUNCATED")
                    break
                if not line.strip():
                    continue
                lines += 1
                counters.update(d.detect_journal_message(line))
        if counters["SSH_ACCEPTED"]:
            self.finding("REMOTE_AUTHENTICATION_REVIEW", "low",
                         "SSH logins observed; compare timestamps and source against your own sessions", "syslog://auth",
                         {"ssh_accepted_count": counters["SSH_ACCEPTED"]}, kind="CONTEXT", attack="T1078")
        self.stats["auth"] = {"source": "syslog_files", "files": files_read, "events_examined": lines,
                              "event_counts": dict(counters), "window_days_max": None, "max_event_lines": event_limit,
                              "event_counts_0_to_72h_after_incident": None}
        if present == 0:
            self.checked("auth", "UNAVAILABLE", "Neither journald nor a syslog authentication file is present; "
                         "cannot infer absence of intrusion", gaps=gaps)
            return
        if lines == 0 and not gaps.incomplete:
            gaps.add("HISTORY_UNAVAILABLE")
        self.conclude("auth", "syslog authentication files (journald absent); whole retained files, no time window; "
                      "no raw messages retained; absence of logging is not absence of incident", gaps, lines)

    # ---- cross-view consistency -------------------------------------------------
    def _proc_self(self) -> Path:
        """Our own /proc entry. On a live host /proc/self and /proc/net are symlinks,
        which the no-follow reader refuses by design; a fixture /proc has a real
        `self` directory. Found by the first 0.2.0 scan of a real host (CV-1)."""
        own = self.proc_root / "self"
        if own.is_symlink():
            return self.proc_root / str(os.getpid())
        return own

    def _listed_pids_and_tids(self) -> tuple[set[int], set[int]] | None:
        listed: set[int] = set()
        tids: set[int] = set()
        try:
            names = [e.name for e in self.proc_root.iterdir() if e.name.isdigit()]
        except OSError:
            # An unreadable proc directory must not masquerade as an empty
            # directory; cross-view negatives depend on a complete listing.
            return None
        for name in names:
            listed.add(int(name))
            try:
                for task in (self.proc_root / name / "task").iterdir():
                    if task.name.isdigit():
                        tids.add(int(task.name))
            except OSError:
                continue
        return listed, tids

    def _tgid_of(self, pid: int) -> int | None | str:
        """Tgid from /proc/<pid>/status; None if the entry is absent; "UNREADABLE" otherwise."""
        raw, status = safe_read(self.proc_root / str(pid) / "status", 16_384)
        if raw is None:
            return None if status == "ABSENT" else "UNREADABLE"
        m = re.search(rb"^Tgid:\s+(\d+)", raw, re.M)
        return int(m.group(1)) if m else "UNREADABLE"

    def _hidden_processes(self, gaps: Gaps, stats: dict[str, Any]) -> None:
        # hidepid is a documented access restriction, not evidence of
        # malicious kernel filtering. Do not promote EPERM to a rootkit alarm.
        if self.scope == "user":
            mountinfo = self._proc_self() / "mountinfo"
            mounts, status = safe_read(mountinfo, 4 * 1024 * 1024)
            if mounts is None:
                # Without mount visibility, EPERM from kill(pid, 0) is not
                # evidence of a hidden process. Refuse negative inference when
                # procfs access policy is unknown or the input is truncated.
                self.read_gap(mountinfo, status, gaps)
                if status == "ABSENT":
                    gaps.add("READ_FAILED")
                stats["processes"] = {"status": "MOUNT_VISIBILITY_UNAVAILABLE",
                                      "hidden": 0, "pid_max_probed": 0}
                return
            mount_policy = _proc_mount_has_hidepid(mounts)
            if mount_policy is None:
                gaps.add("PARSE_UNSUPPORTED")
                stats["processes"] = {"status": "PROC_MOUNT_POLICY_UNDETERMINED",
                                      "hidden": 0, "pid_max_probed": 0}
                return
            if mount_policy:
                gaps.add("OTHER_ACCOUNTS_NOT_VISIBLE")
                stats["processes"] = {"status": "HIDEPID_RESTRICTED", "hidden": 0, "pid_max_probed": 0}
                return
        initial_listing = self._listed_pids_and_tids()
        if initial_listing is None:
            gaps.add("READ_FAILED")
            stats["processes"] = {"status": "PROC_ENUMERATION_UNAVAILABLE",
                                  "hidden": 0, "pid_max_probed": 0}
            return
        listed, tids = initial_listing
        pid_max_path = self.proc_root / "sys/kernel/pid_max"
        raw, status = safe_read(pid_max_path, 64)
        if raw is None:
            # An unknown PID upper bound cannot certify a complete sweep.
            # An absent or unreadable bound is incomplete even when the
            # read error is otherwise reported as a scope limitation.
            self.read_gap(pid_max_path, status, gaps)
            gaps.add("READ_FAILED")
            stats["processes"] = {"status": "PID_MAX_UNAVAILABLE",
                                  "hidden": 0, "pid_max_probed": 0}
            return
        try:
            pid_max = int(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            pid_max = 0
        if pid_max < 1:
            gaps.add("MALFORMED_INPUT")
            stats["processes"] = {"status": "PID_MAX_INVALID",
                                  "hidden": 0, "pid_max_probed": 0}
            return
        if pid_max > PID_SWEEP_MAX:
            # The unprobed tail remains a declared coverage gap.
            gaps.add("ENUMERATION_LIMIT", pid_max - PID_SWEEP_MAX)
            pid_max = PID_SWEEP_MAX
        probed = 0
        candidates: list[int] = []
        for pid in range(1, pid_max + 1):
            if pid % PID_SWEEP_CHUNK == 0 and self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                break
            probed += 1
            if pid in listed or pid in tids or not self.pid_probe(pid):
                continue
            candidates.append(pid)
        hidden: list[dict[str, Any]] = []
        if len(candidates) > 200:
            # The bounded confirmation window cannot establish absence for
            # unexamined candidates; a partial verdict is mandatory.
            gaps.add("ENUMERATION_LIMIT", len(candidates) - 200)
        if candidates:
            time.sleep(PID_RECHECK_DELAY)   # let a process born mid-sweep settle, then confirm
            repeated_listing = self._listed_pids_and_tids()
            if repeated_listing is None:
                gaps.add("READ_FAILED")
                stats["processes"] = {"status": "PROC_RECHECK_UNAVAILABLE",
                                      "pid_max_probed": probed,
                                      "candidates": len(candidates), "hidden": 0}
                return
            listed_again, tids_again = repeated_listing
            for pid in candidates[:200]:
                if pid in listed_again or pid in tids_again or not self.pid_probe(pid):
                    continue
                tgid = self._tgid_of(pid)
                if tgid is None:
                    how = "LOOKUP_AND_LISTING_HIDDEN"     # kill() knows it, procfs denies it exists
                elif tgid == "UNREADABLE":
                    how = "LISTING_HIDDEN_STATUS_UNREADABLE"
                elif tgid == pid:
                    how = "LISTING_HIDDEN"                # lookup works, readdir omits it
                else:
                    continue                             # a thread born after the listing
                hidden.append({"pid": pid, "how": how, "boot_id": self.boot_id, "observed_utc": utc_now()})
        for how in sorted({h["how"] for h in hidden}):
            group = [h for h in hidden if h["how"] == how]
            self.finding("HIDDEN_PROCESS", "high",
                         "A process exists for the kernel (kill probe) but is missing from /proc as listed; "
                         "a procfs-hiding rootkit is one explanation", "crossview://processes",
                         {"how": how}, attack="T1014", observed=group[0])
            for extra in group[1:]:
                self.findings[-1]["observations"].append(extra)
        stats["processes"] = {"pid_max_probed": probed, "listed": len(listed), "threads": len(tids),
                              "candidates": len(candidates), "hidden": len(hidden)}

    def _hidden_modules(self, gaps: Gaps, stats: dict[str, Any]) -> None:
        raw, status = safe_read(self.proc_root / "modules", 1024 * 1024)
        if raw is None:
            self.read_gap(self.proc_root / "modules", status, gaps)
            return
        in_proc = {line.split(b" ", 1)[0].decode("ascii", "replace") for line in raw.splitlines() if line.strip()}
        sys_module = self.sys("/sys/module")
        loaded_in_sys: set[str] = set()
        try:
            for entry in sys_module.iterdir():
                # Built-in modules have no initstate; loaded ones say "live".
                state, _ = safe_read(entry / "initstate", 64)
                if state is not None and state.strip() == b"live":
                    loaded_in_sys.add(entry.name)
        except OSError:
            self.read_gap(sys_module, "FAILED", gaps)
            return
        hidden = sorted(loaded_in_sys - in_proc)
        for name in hidden[:50]:
            self.finding("HIDDEN_KERNEL_MODULE", "high",
                         "A loaded kernel module is present in sysfs but absent from /proc/modules; "
                         "module hiding is a classic rootkit technique", sys_module / name,
                         {"module_name_id": d.digest(name)}, attack="T1014",
                         observed={"module_ref": self.source(name), "observed_utc": utc_now()})
        stats["modules"] = {"proc_modules": len(in_proc), "sysfs_live": len(loaded_in_sys), "hidden": len(hidden)}

    def _procnet_listeners(self) -> set[tuple[str, str, int]] | None:
        found: set[tuple[str, str, int]] = set()
        net = self._proc_self() / "net"
        if not net.is_dir():
            net = self.proc_root / "net"          # fixture without a per-process net directory
        for name, listen_state in (("tcp", "0A"), ("tcp6", "0A"), ("udp", "07"), ("udp6", "07")):
            raw, _ = safe_read(net / name, 8 * 1024 * 1024)
            # Any missing family table invalidates a negative cross-view claim.
            if raw is None:
                return None
            for line in raw.decode("ascii", "replace").splitlines()[1:]:
                fields = line.split()
                if len(fields) < 4:
                    return None
                if fields[3] != listen_state:
                    continue
                endpoint = _proc_listener_endpoint(name, fields[1])
                if endpoint is None:
                    return None
                found.add(endpoint)
        return found

    def _listener_evidence(self, endpoint: tuple[str, str, int], view: str) -> dict:
        """Emit per-scan keyed pseudonym, never plaintext socket bind addresses."""
        secret = getattr(self, "_listener_hash_key", None)
        if secret is None:
            secret = os.urandom(32)
            self._listener_hash_key = secret
        proto_family, address, port = endpoint
        identity = hmac.new(secret, "\0".join((proto_family, address, str(port))).encode("ascii"),
                            hashlib.sha256).hexdigest()[:24]
        return {"proto": proto_family[:-1], "family": "ipv6" if proto_family.endswith("6") else "ipv4",
                "port": port, "local_endpoint_id": identity, "visible_in": view}

    def _hidden_listeners(self, gaps: Gaps, stats: dict[str, Any]) -> None:
        before = self._procnet_listeners()
        if before is None:
            gaps.add("READ_FAILED")
            return
        r = self.command("ss", ["-H", "-tuna", "-p"], timeout=15)
        if r["status"] != "COMPLETED" or r.get("truncated"):
            # Negative inference needs a complete socket table.
            self.command_gap(r, gaps)
            if r["status"] == "PARTIAL" or r.get("truncated"):
                gaps.add("INPUT_TRUNCATED")
            return
        netlink = _ss_listener_endpoints(r["stdout"])
        if netlink is None:
            gaps.add("PARSE_UNSUPPORTED")
            return
        after = self._procnet_listeners()
        if after is None:
            gaps.add("READ_FAILED")
            return
        stable = before & after
        procfs_only = sorted(stable - netlink)
        # A new ss-only endpoint must persist in a second complete observation.
        suspects = netlink - before - after
        confirmed: set[tuple[str, str, int]] = set()
        if suspects:
            again = self.command("ss", ["-H", "-tuna", "-p"], timeout=15)
            if again["status"] == "COMPLETED" and not again.get("truncated"):
                next_netlink = _ss_listener_endpoints(again["stdout"])
                if next_netlink is None:
                    gaps.add("PARSE_UNSUPPORTED")
                else:
                    after_again = self._procnet_listeners()
                    if after_again is None:
                        gaps.add("READ_FAILED")
                    else:
                        confirmed = (suspects & next_netlink) - after_again
            else:
                self.command_gap(again, gaps)
                if again["status"] == "PARTIAL" or again.get("truncated"):
                    gaps.add("INPUT_TRUNCATED")
        netlink_only = sorted(confirmed)
        for endpoint in procfs_only[:50]:
            self.finding("HIDDEN_LISTENER", "high",
                         "A listening socket appears in /proc/net but not in the netlink socket table (ss); "
                         "one of the two views is being filtered", "crossview://listeners",
                         self._listener_evidence(endpoint, "PROCFS_ONLY"), attack="T1014")
        for endpoint in netlink_only[:50]:
            self.finding("HIDDEN_LISTENER", "high",
                         "A listening socket is repeatedly present in ss but absent from /proc/net; "
                         "one kernel view may be filtered", "crossview://listeners",
                         self._listener_evidence(endpoint, "NETLINK_ONLY"), attack="T1014")
        stats["listeners"] = {"procfs": len(stable), "netlink": len(netlink),
                              "procfs_only": len(procfs_only), "netlink_only": len(netlink_only)}
        if suspects - confirmed:
            stats["listeners"]["unconfirmed_netlink_only"] = len(suspects - confirmed)

    def _proc_mount_overlays(self, gaps: Gaps, stats: dict[str, Any]) -> None:
        mountinfo = self._proc_self() / "mountinfo"
        raw, status = safe_read(mountinfo, 4 * 1024 * 1024)
        if raw is None:
            self.read_gap(mountinfo, status, gaps)
            return
        overlays: list[str] = []
        for line in raw.decode("utf-8", "replace").splitlines():
            fields = line.split()
            if len(fields) > 4 and re.fullmatch(r"/proc/\d+(/.*)?", fields[4]):
                overlays.append(fields[4])
        if overlays:
            self.finding("PROC_PID_MOUNT_OVERLAY", "high",
                         "Something is mounted over a /proc/<pid> entry, which hides that process from every reader "
                         "of procfs", "crossview://mounts", {"mount_count": len(overlays)}, attack="T1564.001",
                         observed={"mount_points": sorted(overlays)[:20], "observed_utc": utc_now()})
        stats["proc_pid_mounts"] = len(overlays)

    def crossview(self) -> None:
        """Two kernel views of one fact must agree; disagreement is the finding."""
        gaps = Gaps()
        stats: dict[str, Any] = {}
        self._hidden_processes(gaps, stats)
        self._hidden_modules(gaps, stats)
        self._hidden_listeners(gaps, stats)
        self._proc_mount_overlays(gaps, stats)
        self.stats["crossview"] = stats
        self.conclude("crossview", "Cross-view consistency: PID sweep vs /proc listing, /sys/module vs /proc/modules, "
                      "/proc/net vs netlink, mounts over /proc/<pid>; a rootkit that hooks both views stays unseen",
                      gaps, stats.get("processes", {}).get("pid_max_probed"))

    # (manager, directory or file under the root, extensions or None for every file)
    REPO_CONFIG: tuple[tuple[str, str, frozenset[str] | None], ...] = (
        ("apt", "/etc/apt/sources.list", None), ("apt", "/etc/apt/sources.list.d", frozenset({".list", ".sources"})),
        ("apt", "/etc/apt/apt.conf", None), ("apt", "/etc/apt/apt.conf.d", None),
        ("dnf", "/etc/yum.repos.d", frozenset({".repo"})), ("dnf", "/etc/dnf/dnf.conf", None), ("dnf", "/etc/yum.conf", None),
        ("pacman", "/etc/pacman.conf", None), ("pacman", "/etc/pacman.d", frozenset({".conf"})),
        ("apk", "/etc/apk/repositories", None),
    )

    def _repo_config_files(self, gaps: Gaps) -> list[tuple[str, Path]]:
        """Repository configuration files of every manager, each path once."""
        found: list[tuple[str, Path]] = []
        seen: set[Path] = set()
        for manager, location, extensions in self.REPO_CONFIG:
            path = self.sys(location)
            if path.is_dir() and not path.is_symlink():
                files, _ = self._files([path], extensions=set(extensions) if extensions else None, limit=150, gaps=gaps,
                                       follow_root_links=True)
            elif path.is_file() or path.is_symlink():
                files = [path]
            else:
                continue
            for f in files:
                if f not in seen:
                    seen.add(f)
                    found.append((manager, f))
        return found

    def _integrity_findings(self, manager: str, review: dict, source: str, gaps: Gaps) -> None:
        """One set of rules for every manager; the manager is evidence, not identity."""
        changed_other = review.get("content_changed_other_files", 0)
        conffiles = review.get("content_changed_conffiles", 0)
        if changed_other:
            self.finding("PACKAGE_FILE_DRIFT", "medium",
                         "Installed non-configuration files differ from the package database records", source,
                         {"manager": manager, "content_changed_other_files": changed_other,
                          "content_changed_conffiles": conffiles}, attack="T1554")
        elif conffiles:
            self.finding("PACKAGE_CONFFILE_CHANGED", "low", "Configuration files differ from their packaged versions",
                         source, {"manager": manager, "content_changed_conffiles": conffiles}, kind="CONTEXT")
        if review.get("missing_files"):
            self.finding("PACKAGE_FILES_MISSING", "low", "Files recorded by installed packages are absent on disk",
                         source, {"manager": manager, "missing_files": review["missing_files"],
                                  "missing_by_prefix": review.get("missing_by_prefix", {})}, kind="CONTEXT")
        if review.get("metadata_changed_only"):
            self.finding("PACKAGE_METADATA_DRIFT", "low",
                         "Mode, owner, size or link target of packaged files differ from the records while content matches",
                         source, {"manager": manager, "metadata_changed_only": review["metadata_changed_only"]}, kind="CONTEXT")
        if review.get("unverifiable"):
            gaps.add("REQUIRES_SYSTEM_SCOPE" if self.scope == "user" else "PERMISSION_DENIED", review["unverifiable"])

    def _verify_with_command(self, manager: str, tool: str, args: list[str], classify: Callable[[str], dict],
                             gaps: Gaps) -> dict | None:
        verify = self.command(tool, args, timeout=110, limit=4 * 1024 * 1024)
        # Both tools exit non-zero when they report differences; output is the result.
        if verify["status"] in ("COMPLETED", "PARTIAL") or (verify["exit"] in (1, 2) and bool(verify["stdout"])):
            review = classify(verify["stdout"])
            review.update({"unverified_after_cap": verify["truncated"], "command_exit": verify["exit"]})
        else:
            self.command_gap(verify, gaps)
            review = None
            self.stats.setdefault("package_integrity", {})[manager] = {"status": verify["status"], "error": verify["error"]}
        if verify["truncated"]:
            gaps.add("INPUT_TRUNCATED")
        return review

    def _verify_recorded(self, manager: str, records: dict[str, tuple[str, str]], modes: dict[str, int], gaps: Gaps) -> dict:
        """Compare recorded digests with the files on disk, within VERIFY_* bounds."""
        review: dict[str, Any] = {"content_changed_conffiles": 0, "content_changed_other_files": 0, "missing_files": 0,
                                  "unverifiable": 0, "metadata_changed_only": 0, "unparsed_lines": 0,
                                  "files_checked": 0, "bytes_hashed": 0, "records": len(records), "truncated": False}
        prefixes: dict[str, int] = {}
        selected = sorted(rel for rel in records if rel.startswith(VERIFY_PREFIXES))
        review["records_in_scope"] = len(selected)
        for rel in selected:
            if self.over_budget():
                gaps.add("BUDGET_EXHAUSTED")
                review["truncated"] = True
                break
            if review["files_checked"] >= VERIFY_MAX_FILES or review["bytes_hashed"] >= VERIFY_MAX_BYTES:
                gaps.add("ENUMERATION_LIMIT")
                review["truncated"] = True
                break
            algorithm, expected = records[rel]
            path = self.sys(rel)
            try:
                info = path.lstat()
            except FileNotFoundError:
                review["missing_files"] += 1
                prefix = "/" + "/".join(rel.strip("/").split("/")[:3])
                prefixes[prefix] = prefixes.get(prefix, 0) + 1
                continue
            except OSError:
                review["unverifiable"] += 1
                continue
            if not stat.S_ISREG(info.st_mode):
                review["metadata_changed_only"] += 1  # recorded as a file, found as something else
                continue
            content, status = safe_read(path, VERIFY_MAX_FILE_BYTES)
            review["files_checked"] += 1
            if content is None:
                review["unverifiable"] += 1
                continue
            review["bytes_hashed"] += len(content)
            if not self._digest_matches(content, algorithm, expected):
                review["content_changed_conffiles" if rel.startswith("/etc/") else "content_changed_other_files"] += 1
            elif rel in modes and stat.S_IMODE(info.st_mode) != modes[rel]:
                review["metadata_changed_only"] += 1
        review["missing_by_prefix"] = dict(sorted(prefixes.items(), key=lambda kv: (-kv[1], kv[0]))[:10])
        return review

    def _verify_pacman(self, gaps: Gaps) -> dict:
        records = self._pacman_records()
        modes: dict[str, int] = {}
        local = self.sys("/var/lib/pacman/local")
        try:
            folders = sorted(p for p in local.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            folders = []
        malformed = 0
        for folder in folders[:PACKAGE_DB_MAX_RECORDS]:
            data = self._read_mtree(folder / "mtree")
            if data is None:
                continue
            entries, stats = pk.parse_pacman_mtree(data)
            malformed += stats["malformed"]
            for rel, attrs in entries.items():
                if attrs.get("type") == "file" and "mode" in attrs:
                    modes[rel] = attrs["mode"]
        review = self._verify_recorded("pacman", records, modes, gaps)
        review["unparsed_lines"] = malformed
        return review

    def _verify_apk(self, gaps: Gaps) -> dict:
        records = self._apk_records()
        modes: dict[str, int] = {}
        raw, status = safe_read(self.sys("/lib/apk/db/installed"), APK_DB_MAX_BYTES)
        malformed = omitted_lines = 0
        truncated = False
        if raw is None:
            if status == "ABSENT":
                # A previously detected package manager lost its installed index.
                gaps.add("READ_FAILED")
            else:
                self.read_gap(self.sys("/lib/apk/db/installed"), status, gaps)
        else:
            db, stats = pk.parse_apk_installed(raw)
            malformed = stats["malformed"]
            truncated = stats["truncated"]
            if malformed:
                gaps.add("MALFORMED_INPUT", malformed)
            if truncated:
                omitted_lines = len(raw.splitlines()) - stats["lines"]
                gaps.add("ENUMERATION_LIMIT", omitted_lines)
            modes = {rel: info["mode"] for rel, info in db["files"].items() if "mode" in info}
        review = self._verify_recorded("apk", records, modes, gaps)
        review["unparsed_lines"] = malformed
        review["reference_lines_omitted"] = omitted_lines
        review["truncated"] = review["truncated"] or truncated
        return review

    def packages(self) -> None:
        managers = self.managers()
        installed = {}
        if "dpkg" in managers:
            names = ("openssh-server", "anydesk", "rustdesk", "teamviewer", "x11vnc", "tigervnc-standalone-server",
                     "chrome-remote-desktop", "clamav", "auditd", "apparmor", "ufw", "firefox", "google-chrome-stable", "brave-browser")
            for name in names:
                # dpkg-query is not used: direct passive check of dpkg metadata only.
                raw, st = safe_read(self.sys("/var/lib/dpkg/info") / f"{name}.list", 128*1024)
                if raw:
                    installed[name] = True
        self.stats["packages"] = {"managers": managers, "selected_package_filelists_present": sorted(installed)}
        gaps = Gaps()
        repos = self._repo_config_files(gaps)
        insecure_repo_files = 0
        for manager, p in repos:
            raw, st = safe_read(p, 256 * 1024)
            if raw is None:
                self.read_gap(p, st, gaps)
                continue
            codes = pk.detect_insecure_repo_settings(manager, raw.decode("utf-8", "replace"))
            if codes:
                insecure_repo_files += 1
                self.finding("INSECURE_PACKAGE_SOURCE_SETTING", "medium",
                             "Package source configuration disables signature or transport trust checks", p,
                             {"manager": manager, "codes": codes}, kind="HARDENING", attack="T1195.002")
        if self.profile == "deep":
            integrity: dict[str, Any] = self.stats.setdefault("package_integrity", {})
            review: dict | None
            if "dpkg" in managers and self.offline:
                # dpkg --verify would examine the live host; compare the image's md5sums records with its files.
                self._dpkg_md5(self.sys("/"))  # build the index
                records = {rel: ("md5", digest) for rel, digest in (self._dpkg_index or {}).items()}
                offline_review = self._verify_recorded("dpkg", records, {}, gaps)
                integrity["dpkg"] = offline_review
                self._integrity_findings("dpkg", offline_review, "dpkg://md5sums", gaps)
            elif "dpkg" in managers:
                review = self._verify_with_command("dpkg", "dpkg", ["--verify"], d.dpkg_verify_review, gaps)
                if review is not None:
                    integrity["dpkg"] = review
                    self._integrity_findings("dpkg", review, "dpkg://verify", gaps)
            if "rpm" in managers and self.offline:
                gaps.add("LIVE_ONLY_NOT_IN_OFFLINE_IMAGE")   # rpm's binary database is not parsed
                integrity["rpm"] = {"status": "SKIPPED", "error": "OFFLINE_IMAGE"}
            elif "rpm" in managers:
                review = self._verify_with_command("rpm", "rpm", ["-Va"], pk.rpm_verify_review, gaps)
                if review is not None:
                    integrity["rpm"] = review
                    self._integrity_findings("rpm", review, "rpm://verify", gaps)
            if "pacman" in managers:
                review = self._verify_pacman(gaps)
                integrity["pacman"] = review
                self._integrity_findings("pacman", review, "pacman://mtree", gaps)
            if "apk" in managers:
                review = self._verify_apk(gaps)
                integrity["apk"] = review
                self._integrity_findings("apk", review, "apk://installed", gaps)
            if not managers:
                integrity["none"] = {"status": "NO_PACKAGE_DATABASE"}
            detail = ("Package source trust settings + package integrity (dpkg --verify, rpm -Va, pacman mtree and apk "
                      "database digests compared with disk within fixed bounds). Drift is not malware attribution")
        else:
            gaps.add("NOT_IN_PROFILE")
            detail = "Package source trust settings and selected package metadata; integrity verification runs only in the deep profile"
        if self.profile == "deep":
            for manager, counts in self._package_db_gaps.items():
                if manager in managers:
                    integrity.setdefault(manager, {})["reference_db_omissions"] = dict(sorted(counts.items()))
                    for code, count in counts.items():
                        gaps.add(code, count)
        self.stats["repos"] = {"source_files_checked": len(repos), "insecure_source_files": insecure_repo_files}
        self.conclude("packages", detail, gaps, len(repos))

    def kernel(self) -> None:
        stats: dict[str, Any] = {}
        gaps = Gaps()
        for name, path in (("taint", "/proc/sys/kernel/tainted"), ("modules", "/proc/modules"),
                           ("lsm", "/sys/kernel/security/lsm")):
            raw, st = safe_read(self.sys(path), 256*1024 if name == "modules" else 4096)
            if raw is None:
                stats[name + "_status"] = st
                self.read_gap(self.sys(path), st, gaps)
                continue
            if name == "modules":
                stats["module_count"] = len(raw.splitlines())
                # Module names may be attacker-controlled: retain only hashes.
                stats["module_name_ids"] = [d.digest(l.split(b" ", 1)[0]) for l in raw.splitlines()[:150]]
            else:
                stats[name] = raw.decode("utf-8", "replace").strip()[:200]
        aa = self.command("aa-status", ["--enabled"], timeout=7)
        stats["apparmor_cmd_status"] = aa["status"]
        stats["apparmor_enabled_exit"] = aa["exit"]
        # aa-status --enabled answers by exit code: 0 enabled, non-zero not enabled.
        if aa["status"] == "UNAVAILABLE":
            gaps.add("TOOL_MISSING")
        elif aa["exit"] is None:
            self.command_gap(aa, gaps)
        if self.scope == "system":
            mok = self.command("mokutil", ["--sb-state"], timeout=7)
            stats["secure_boot_status"] = "UNKNOWN" if mok["status"] != "COMPLETED" else (
                "ENABLED" if "SecureBoot enabled" in mok["stdout"] else "DISABLED_OR_UNSUPPORTED")
            self.command_gap(mok, gaps)
        else:
            gaps.add("REQUIRES_SYSTEM_SCOPE")
        if self.profile_config["journal_lines"]:
            sample = self.profile_config["journal_lines"] // 4
            kr = self._journal(["_TRANSPORT=kernel"], 30, sample, 30)
            if kr["status"] in ("COMPLETED", "PARTIAL"):
                counters, _, lines, _, _ = self._journal_signals(kr["stdout"])
                # Declared as a recent sample, not as history: no completeness claim.
                stats["kernel_log_sample"] = {"most_recent_messages": lines, "sample_cap": sample,
                                              "signal_counts": dict(counters)}
            else:
                self.command_gap(kr, gaps)
        self.stats["kernel"] = stats
        self.conclude("kernel", "Kernel taint/modules/LSM/AppArmor/Secure Boot signals and a recent kernel-log sample. Cannot rule out kernel/rootkit/firmware compromise",
                      gaps)
