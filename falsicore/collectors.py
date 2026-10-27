"""Bounded passive collectors for Linux. No socket connections or command execution of artifacts."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import pwd
import re
import stat
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from . import detectors as d
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
        "dpkg": ["--verify"], "aa-status": ["--enabled"],
        "mokutil": ["--sb-state"],
    }
    if name in exact:
        return args == exact[name]
    if name == "crontab":
        return args == ["-l"] or (len(args) == 3 and args[:2] == ["-l", "-u"]
                                       and bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args[2])))
    if name == "journalctl":
        return (len(args) == 7 and args[0] == "--since"
                and bool(re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", args[1]))
                and args[2] == "--lines" and args[3].isdigit() and len(args[3]) <= 5
                and 0 <= int(args[3]) <= 10000 and args[4:] == [
                    "--no-pager", "--output=json",
                    "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"])
    return False

MAX_FILES_PER_COLLECTION = 2000
MAX_PROCESSES = 6000
MAX_FINDINGS = 350


class Audit:
    def __init__(self, scope: str, target_user: str | None = None, incident_at: str | None = None,
                 profile: str = "standard", max_seconds: int | None = None):
        if scope not in ("user", "system"):
            raise ValueError("scope must be user or system")
        if scope == "system" and os.geteuid() != 0:
            raise PermissionError("System scope requires explicit root invocation")
        if scope == "user" and os.geteuid() == 0:
            raise PermissionError("Run user scope without root privileges")
        if scope == "system" and not target_user:
            raise ValueError("System scope requires --target-user")
        target = target_user or pwd.getpwuid(os.getuid()).pw_name
        entry = pwd.getpwnam(target)
        if entry.pw_uid == 0:
            raise ValueError("Refusing to treat root as browser user")
        self.profile = profile
        self.profile_config = config_for(profile)
        if max_seconds is not None and not 5 <= max_seconds <= 600:
            raise ValueError("--max-seconds must be 5..600")
        self.max_seconds = max_seconds or self.profile_config["duration_seconds"]
        self.deadline: float | None = None
        self.phase_timings: dict[str, int] = {}
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
        self.suspicious_exec_pids: set[int] = set()
        self.incident_at = None
        if incident_at:
            try:
                anchor = dt.datetime.fromisoformat(incident_at.replace("Z", "+00:00"))
            except (TypeError, ValueError) as exc:
                raise ValueError("--incident-at must be ISO 8601 with timezone") from exc
            if anchor.tzinfo is None:
                raise ValueError("--incident-at must include timezone offset (e.g. +02:00)")
            self.incident_at = anchor.astimezone(dt.timezone.utc)

    def source(self, text: str | Path) -> str:
        """Public reports contain an opaque ID; path only in local private_index."""
        raw = str(text)
        ref = "src_" + d.digest(raw, 24)
        self.private_index[ref] = raw
        return ref

    def finding(self, rule: str, severity: str, hypothesis: str, source: str | Path,
                evidence: dict | None = None, kind: str = "INDICATOR", attack: str = "") -> None:
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
        })

    def checked(self, name: str, status: str, details: str, sources: int | None = None) -> None:
        if status not in ("COMPLETED", "PARTIAL", "FAILED", "UNAVAILABLE", "SKIPPED"):
            raise ValueError(status)
        item: dict[str, Any] = {"check": name, "status": status, "details": details}
        if sources is not None:
            item["sources_inspected"] = sources
        self.coverage.append(item)

    def command(self, tool: str, args: list[str], timeout: int = 12, limit: int = 2*1024*1024) -> dict:
        if not _allowed_audit_invocation(tool, args):
            raise PermissionError("Collector command is not an approved read-only probe")
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

    def scan(self) -> None:
        started = time.monotonic()
        self.deadline = started + self.max_seconds
        for name in COLLECTOR_ORDER:
            if name not in self.profile_config["checks"]:
                self.checked(name, "SKIPPED", f"Excluded by {self.profile} profile; not a negative result")
                continue
            if self.over_budget():
                self.checked(name, "SKIPPED", "Runtime budget exhausted before collector started")
                continue
            previous_checks = len(self.coverage)
            tick = time.monotonic()
            # A failed collector must not contribute findings, baseline state or
            # partially computed metrics. Keep its command audit for provenance.
            checkpoint = (
                len(self.findings), self.dropped_findings, self._next,
                copy.deepcopy(self.stats), copy.deepcopy(self.baseline),
                dict(self.private_index), set(self.suspicious_exec_pids),
            )
            try:
                getattr(self, name)()
            except Exception as exc:
                self._rollback_collector(checkpoint, previous_checks)
                self.checked(name, "FAILED", f"collector failed; discarded incomplete observations ({type(exc).__name__})")
                self.stats[f"{name}_exception"] = type(exc).__name__
            else:
                if not any(c["check"] == name for c in self.coverage[previous_checks:]):
                    self._rollback_collector(checkpoint, previous_checks)
                    self.checked(name, "FAILED", "Collector returned without a coverage result; discarded incomplete observations")
                elif self.over_budget():
                    for c in self.coverage[previous_checks:]:
                        if c["check"] == name and c["status"] == "COMPLETED":
                            c["status"] = "PARTIAL"
                            c["details"] += "; runtime budget exceeded"
            self.phase_timings[name] = max(0, int((time.monotonic() - tick) * 1000))
        if self.dropped_findings:
            self.checked("finding_capacity", "PARTIAL", f"{self.dropped_findings} findings omitted (limit {MAX_FINDINGS})")
        self.stats["runtime"] = {"elapsed_ms": int((time.monotonic() - started) * 1000),
                                  "budget_seconds": self.max_seconds,
                                  "phase_elapsed_ms": self.phase_timings,
                                  "profile": self.profile}
        self.deadline = None

    def environment(self) -> None:
        raw, status = safe_read(Path("/etc/os-release"), limit=16_384)
        os_release_source = "/etc/os-release"
        if raw is None:
            # /etc/os-release -> ../usr/lib/os-release is the normal systemd
            # arrangement on Ubuntu. Do NOT relax the general no-symlink read
            # policy; read the fixed vendor path independently instead.
            fallback, fallback_status = safe_read(Path("/usr/lib/os-release"), limit=16_384)
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
            value, _ = safe_read(Path(f), 64)
            if value is not None:
                self.stats[f"sysctl_{Path(f).name}"] = value.decode("ascii", "replace").strip()
        self.checked("environment", "COMPLETED" if raw and kernel["status"] == "COMPLETED" else "PARTIAL",
                     "Local OS/kernel metadata (fixed vendor fallback for os-release symlink), selected policy sysctls; no runtime attestation")

    def processes(self) -> None:
        root = getattr(self, "proc_root", Path("/proc"))
        total = 0
        denied = 0
        disappeared = 0
        exeids: set[str] = set()
        browser_seen = 0
        for entry in root.iterdir():
            if self.over_budget():
                break
            if not entry.name.isdigit():
                continue
            total += 1
            if total > self.profile_config["max_processes"] or self.over_budget():
                break
            pid = entry.name
            status_raw, st = safe_read(entry / "status", 16_384)
            if status_raw is None:
                if st == "PERMISSION_DENIED":
                    denied += 1
                else:
                    disappeared += 1
                continue
            data = status_raw.decode("utf-8", "replace")
            uid_match = re.search(r"^Uid:\s+(\d+)", data, re.M)
            if uid_match is None:
                continue
            uid = int(uid_match.group(1))
            try:
                exe = os.readlink(entry / "exe")
            except PermissionError:
                denied += 1
                continue
            except (FileNotFoundError, OSError):
                disappeared += 1
                continue
            ppid_match = re.search(r"^PPid:\s+(\d+)", data, re.M)
            exeids.add(d.digest(exe))
            for rule, severity in d.classify_executable(exe, uid, deleted=exe.endswith(" (deleted)")):
                if rule == "EXECUTABLE_IN_VOLATILE_PATH":
                    self.suspicious_exec_pids.add(int(pid))
                self.finding(rule, severity, "Potential unauthorized execution or persistence", entry / "exe",
                             {"uid": uid, "pid": int(pid), "ppid": int(ppid_match.group(1)) if ppid_match else None,
                              "exe_id": d.digest(exe)})
            if any(b in exe.lower() for b in ("chrome", "chromium", "firefox", "brave")):
                browser_seen += 1
                cmdraw, st = safe_read(entry / "cmdline", 8192)
                if cmdraw:
                    args = [x.decode("utf-8", "replace") for x in cmdraw.split(b"\0") if x]
                    flags = d.analyze_browser_flags(args)
                    if flags:
                        self.finding("UNSAFE_BROWSER_LAUNCH_FLAG", "medium", "Browser sandbox/network weakening or inspectable debugging", entry / "cmdline",
                                     {"pid": int(pid), "flags": flags}, kind="EXPOSURE")
        self.baseline["process_exe_hashes"] = sorted(exeids)
        self.stats["processes"] = {"enumerated": min(total, self.profile_config["max_processes"]), "denied": denied,
                                   "disappeared": disappeared, "browser_processes": browser_seen}
        partial = denied > 0 or total > self.profile_config["max_processes"] or self.over_budget()
        self.checked("processes", "PARTIAL" if partial else "COMPLETED",
                     "Live /proc metadata only; process lists cannot prove absence of rootkits; command lines not exported", min(total, self.profile_config["max_processes"]))

    def network(self) -> None:
        r = self.command("ss", ["-H", "-tuna", "-p"], timeout=15)
        if r["status"] not in ("COMPLETED", "PARTIAL"):
            self.checked("network", r["status"], "ss unavailable or failed; no active network scan")
            return
        sockets = d.parse_ss(r["stdout"])
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
        self.checked("network", "COMPLETED" if r["status"] == "COMPLETED" and not missing_owner else "PARTIAL",
                     "One-time ss snapshot; remote endpoint literals only in private_index.json; no packet history or absent process attribution", len(sockets))

    def _mtime_near_incident(self, path: Path) -> bool | None:
        if not self.incident_at:
            return None
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
            return abs((mtime - self.incident_at).total_seconds()) <= 72 * 3600
        except OSError:
            return None

    def _files(self, bases: Iterable[Path], extensions: set[str] | None = None,
               recursive: bool = False, limit: int = MAX_FILES_PER_COLLECTION) -> tuple[list[Path], bool]:
        out: list[Path] = []
        incomplete = False
        visits = 0
        visit_budget = self.profile_config["max_file_visits"]
        for base in bases:
            if self.over_budget():
                return out, True
            try:
                if base.is_symlink():
                    incomplete = True
                    continue
                if not base.is_dir():
                    continue
                # os.walk can silently skip unreadable nested folders unless
                # onerror is installed: a skipped subtree is a coverage gap.
                def walk_error(_exc: OSError) -> None:
                    nonlocal incomplete
                    incomplete = True
                walker = (os.walk(base, topdown=True, followlinks=False, onerror=walk_error)
                          if recursive else [(str(base), [], os.listdir(base))])
                for folder, dirs, names in walker:
                    visits += 1
                    if visits > visit_budget or self.over_budget():
                        return out, True
                    if any((Path(folder) / x).is_symlink() for x in dirs):
                        incomplete = True
                    dirs[:] = sorted(x for x in dirs if not (Path(folder) / x).is_symlink())
                    for name in sorted(names):
                        visits += 1
                        if visits > visit_budget or self.over_budget():
                            return out, True
                        path = Path(folder) / name
                        if path.is_symlink():
                            incomplete = True
                            continue
                        if not path.is_file():
                            continue
                        if extensions is None or path.suffix.lower() in extensions:
                            if len(out) >= limit:
                                return out, True
                            out.append(path)
            except (PermissionError, OSError):
                incomplete = True
        return out, incomplete

    def persistence(self) -> None:
        units = [Path("/etc/systemd/system"), Path("/etc/systemd/user"),
                 self.home / ".config/systemd/user"]
        # Package-supplied units also participate in persistence, and can be
        # modified by privileged attackers. Do not mistake /etc-only for full
        # systemd coverage. /lib is usually a symlink to /usr/lib on Ubuntu.
        vendor_units = Path("/usr/lib/systemd/system")
        if vendor_units.is_dir() and not vendor_units.is_symlink():
            units.append(vendor_units)
        else:
            fallback = Path("/lib/systemd/system")
            if fallback.is_dir() and not fallback.is_symlink():
                units.append(fallback)
        units_found, trunc = self._files(units, extensions={".service", ".timer", ".socket"}, recursive=True, limit=2600)
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
                        unreadable += 1
                        break
                    dirs[:] = sorted(x for x in dirs if not (Path(folder) / x).is_symlink())
                    for name in sorted(names):
                        visits += 1
                        if visits > self.profile_config["max_file_visits"] or self.over_budget():
                            unreadable += 1
                            break
                        p = Path(folder) / name
                        if p.suffix != ".service" or not p.is_symlink():
                            continue
                        symlink_count += 1
                        try:
                            target = os.readlink(p)
                        except OSError:
                            unreadable += 1
                            continue
                        if any(v in target for v in d.SUSPICIOUS_PATHS):
                            self.finding("SYSTEMD_SYMLINK_TO_TEMP", "high", "Service symlink resolves through volatile path", p,
                                         {"target_ref": d.digest(target)}, attack="T1543.002")
            except (OSError, PermissionError):
                unreadable += 1
        for p in units_found:
            if self.over_budget():
                unreadable += 1
                break
            raw, st = safe_read(p, 128 * 1024)
            if raw is None:
                unreadable += 1
                continue
            count += 1
            self.baseline["systemd_units"].append(d.digest(str(p) + ":" + hashlib.sha256(raw).hexdigest()))
            if p.suffix == ".service":
                rules = d.suspicious_systemd(raw.decode("utf-8", "replace"))
                if rules:
                    temporal = self._mtime_near_incident(p)
                    self.finding("SUSPICIOUS_SYSTEMD_EXECUTION", "high", "Service may execute from volatile location or fetch a remote script", p,
                                 {"pattern_rules": rules, "mtime_near_incident_72h": temporal}, attack="T1543.002")
        loader, loader_status = safe_read(Path("/etc/ld.so.preload"), 8192)
        if loader:
            self.finding("SYSTEM_LOADER_PRELOAD", "medium", "Dynamic loader system preload is configured; verify provenance", "/etc/ld.so.preload",
                         {"entry_count": len([l for l in loader.splitlines() if l.strip()])}, kind="INDICATOR", attack="T1574.006")
        cronfiles, crontrunc = self._files(
            [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"), Path("/etc/cron.weekly"),
             Path("/etc/cron.monthly"), self.home / ".config/cron"], recursive=False, limit=500)
        for p in cronfiles:
            if self.over_budget():
                unreadable += 1
                break
            raw, st = safe_read(p, 64 * 1024)
            if raw is None:
                unreadable += 1
                continue
            self.baseline["cron_entry_hashes"].append(d.digest(str(p) + ":" + hashlib.sha256(raw).hexdigest()))
            flags = d.suspect_command(cron_commands(raw.decode("utf-8", "replace"), system=p.parent == Path("/etc/cron.d")))
            if flags:
                self.finding("SUSPICIOUS_CRON_EXECUTION", "high", "Cron includes risky command pattern", p,
                             {"patterns": flags}, attack="T1053.003")
        cr = self.command("crontab", ["-l", "-u", self.target_user] if self.scope == "system" else ["-l"], timeout=6, limit=64*1024)
        if cr["status"] == "COMPLETED":
            cron = cr["stdout"]
            self.baseline["cron_entry_hashes"].extend(d.digest(line) for line in cron.splitlines() if line.strip() and not line.lstrip().startswith("#"))
            flags = d.suspect_command(cron_commands(cron))
            if flags:
                self.finding("SUSPICIOUS_USER_CRONTAB", "high", "User cron includes command execution concerns", "crontab://target-user", {"patterns": flags}, attack="T1053.003")
        for p in (self.home / ".ssh/authorized_keys", self.home / ".ssh/authorized_keys2"):
            raw, st = safe_read(p, 128 * 1024)
            if raw is None and st not in ("ABSENT",):
                ssh_unreadable += 1
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
        for p in (self.home / ".bashrc", self.home / ".profile", self.home / ".bash_profile", self.home / ".zshrc", self.home / ".config/fish/config.fish"):
            raw, st = safe_read(p, 128 * 1024)
            if raw is None and st != "ABSENT":
                unreadable += 1
            if raw:
                analysis = analyze_shell(raw.decode("utf-8", "replace"))
                rules = analysis["patterns"]
                if analysis["limitations"]:
                    self.stats.setdefault("shell_analysis_limits", []).append({
                        "source_ref": self.source(p), "limitations": analysis["limitations"]})
                if rules:
                    self.finding("SUSPICIOUS_SHELL_INIT", "medium", "Shell initialization contains literal risky command syntax; not proof of execution", p,
                                 {"patterns": rules, "file_name": p.name, "locations": analysis["matches"],
                                  "limitations": analysis["limitations"]}, attack="T1546.004")
        autostart, a_trunc = self._files([self.home / ".config/autostart", Path("/etc/xdg/autostart")], extensions={".desktop"}, limit=300)
        for p in autostart:
            raw, st = safe_read(p, 64 * 1024)
            if raw is None:
                unreadable += 1
            if raw:
                rules = d.suspect_command(desktop_commands(raw.decode("utf-8", "replace")))
                if rules:
                    self.finding("SUSPICIOUS_AUTOSTART", "medium", "Autostart entry references risky execution", p,
                                 {"patterns": rules}, attack="T1547.013")
        s_trunc = False
        if self.scope == "system":
            sudoers, s_trunc = self._files([Path("/etc/sudoers.d")], limit=300)
            for p in sudoers:
                raw, st = safe_read(p, 32 * 1024)
                if raw is None:
                    unreadable += 1
                if raw and b"NOPASSWD:" in raw:
                    self.finding("SUDO_NOPASSWD_RULE", "low", "Passwordless sudo policy present; authorization must be reviewed", p,
                                 {"configuration_present": True}, kind="HARDENING")
        self.stats["persistence"] = {"systemd_units_read": count, "cron_files_found": len(cronfiles),
                                     "autostart_found": len(autostart), "authorized_keys_count": len(self.baseline["ssh_key_fingerprints"]),
                                     "unreadable": unreadable, "ssh_unreadable": ssh_unreadable,
                                     "systemd_symlink_count": symlink_count}
        cron_absent = cr["status"] == "FAILED" and "no crontab for" in cr.get("stdout", "").lower()
        incomplete = (trunc or crontrunc or a_trunc or s_trunc or unreadable > 0 or ssh_unreadable > 0
                      or (cr["status"] != "COMPLETED" and not cron_absent)
                      or bool(self.stats.get("shell_analysis_limits")))
        self.checked("persistence", "PARTIAL" if incomplete else "COMPLETED",
                     "Selected systemd/custom units (including symlink metadata), cron, SSH public-key hashes, shell and XDG autoruns; shell analysis is a lexical subset, not full Bash evaluation",
                     len(units_found) + len(cronfiles) + len(autostart))

    def _scan_chromium(self, name: str, base: Path) -> tuple[int, int, bool]:
        if base.is_symlink():
            return 0, 0, True
        if not base.is_dir():
            return 0, 0, False
        ext_count, profile_count, truncated = 0, 0, False
        profiles = []
        try:
            for p in base.iterdir():
                if p.is_dir() and not p.is_symlink() and (p.name == "Default" or p.name.startswith("Profile ")):
                    profiles.append(p)
        except (PermissionError, OSError):
            return 0, 0, True
        for prof in sorted(profiles, key=lambda p: p.name)[:30]:
            if self.over_budget():
                truncated = True
                break
            profile_count += 1
            exts = prof / "Extensions"
            if exts.is_symlink():
                truncated = True
                continue
            if not exts.is_dir():
                continue
            try:
                ext_ids = sorted(exts.iterdir(), key=lambda p: p.name)[:201]
            except (OSError, PermissionError):
                truncated = True
                continue
            if len(ext_ids) > 200:
                truncated = True
            for extdir in ext_ids[:200]:
                if self.over_budget():
                    truncated = True
                    break
                if extdir.is_symlink():
                    truncated = True
                    continue
                if not extdir.is_dir():
                    truncated = True
                    continue
                try:
                    versions = sorted((x for x in extdir.iterdir() if x.is_dir() and not x.is_symlink()),
                                      key=_extension_version_key, reverse=True)
                except (OSError, PermissionError):
                    truncated = True
                    continue
                if not versions:
                    truncated = True
                for version in versions[:1]:
                    manifest_path = version / "manifest.json"
                    raw, st = safe_read(manifest_path, d.MAX_JSON_BYTES)
                    if raw is None:
                        # A discovered version directory with no readable
                        # manifest cannot be asserted to have been inspected.
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
                    if r["risk_flag"]:
                        self.finding("POWERFUL_BROWSER_EXTENSION", "medium", "Browser extension may access sensitive web content or browser capabilities", manifest_path,
                                     {"browser": name, "extension_ref": ext_id,
                                      "sensitive_permissions": r["sensitive_permissions"],
                                      "broad_host_access": r["broad_host_access"],
                                      "instagram_access_potential": r["instagram_access_potential"],
                                      "content_script_instagram_access": r["content_script_instagram_access"]},
                                     kind="EXPOSURE", attack="T1176.001")
        return ext_count, profile_count, truncated or len(profiles) > 30

    def _scan_firefox(self, base: Path | None = None, label: str = "firefox") -> tuple[int, bool]:
        base = base or (self.home / ".mozilla/firefox")
        if base.is_symlink():
            return 0, True
        if not base.is_dir():
            return 0, False
        profiles = []
        try:
            entries = list(base.iterdir())
            profiles = [x for x in entries if x.is_dir() and not x.is_symlink() and (".default" in x.name or ".release" in x.name)]
            skipped_links = any(x.is_symlink() and (".default" in x.name or ".release" in x.name) for x in entries)
        except (OSError, PermissionError):
            return 0, True
        count = 0
        truncated = len(profiles) > 30 or skipped_links
        for prof in sorted(profiles, key=lambda p: p.name)[:30]:
            if self.over_budget():
                truncated = True
                break
            path = prof / "extensions.json"
            raw, st = safe_read(path, d.MAX_JSON_BYTES)
            if raw is None:
                # Missing, unreadable or oversized profile metadata means
                # extension grants were not independently assessed.
                truncated = True
                continue
            try:
                obj = d.safe_json_parse(raw)
                addons = obj.get("addons", []) if isinstance(obj, dict) else []
                if not isinstance(addons, list):
                    truncated = True
                    continue
            except (ValueError, TypeError, json.JSONDecodeError):
                truncated = True
                continue
            if len(addons) > 200:
                truncated = True
            for addon in addons[:200]:
                if not isinstance(addon, dict):
                    truncated = True
                    continue
                if addon.get("type") not in ("extension", None):
                    continue
                count += 1
                aid = d.digest(str(addon.get("id", "unknown")), 24)
                self.baseline["browser_extensions"].append(f"{label}:{aid}:{d.digest(json.dumps(addon, sort_keys=True))}")
                perms = addon.get("userPermissions", {})
                if isinstance(perms, dict):
                    p = [x for x in perms.get("permissions", []) if isinstance(x, str)] if isinstance(perms.get("permissions", []), list) else []
                    o = [x for x in perms.get("origins", []) if isinstance(x, str)] if isinstance(perms.get("origins", []), list) else []
                    review = d.extension_assessment({"permissions": p, "host_permissions": o})
                    # Disabled add-ons are inventoried but not presented as active exposure.
                    if review["risk_flag"] and addon.get("active", True) is not False and addon.get("userDisabled") is not True and addon.get("appDisabled") is not True:
                        self.finding("POWERFUL_FIREFOX_EXTENSION", "medium", "Firefox extension has powerful host/API permissions", path,
                                     {"browser": label, "extension_ref": aid,
                                      "sensitive_permissions": review["sensitive_permissions"],
                                      "broad_host_access": review["broad_host_access"],
                                      "instagram_access_potential": review["instagram_access_potential"]},
                                     kind="EXPOSURE", attack="T1176.001")
        return count, truncated

    def browsers(self) -> None:
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
        incomplete = False
        for name, path in chromium.items():
            ext, profiles, truncated = self._scan_chromium(name, path)
            stats[name] = {"profiles": profiles, "extensions": ext, "profile_scan_limited": truncated}
            incomplete |= truncated
        firefox_paths = {
            "firefox": self.home / ".mozilla/firefox",
            "firefox-snap": self.home / "snap/firefox/common/.mozilla/firefox",
            "firefox-flatpak": self.home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
        }
        for label, base in firefox_paths.items():
            count, trunc = self._scan_firefox(base, label)
            stats[label] = {"extensions": count, "profile_scan_limited": trunc}
            incomplete |= trunc
        native_dirs = [
            self.home / ".config/google-chrome/NativeMessagingHosts",
            self.home / ".config/chromium/NativeMessagingHosts",
            self.home / ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
            self.home / ".mozilla/native-messaging-hosts",
            self.home / "snap/firefox/common/.mozilla/native-messaging-hosts",
            self.home / ".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts",
            Path("/etc/opt/chrome/native-messaging-hosts"),
            Path("/etc/chromium/native-messaging-hosts"),
            Path("/usr/lib/mozilla/native-messaging-hosts"),
        ]
        natives, trunc = self._files(native_dirs, extensions={".json"}, limit=250)
        incomplete |= trunc
        for path in natives:
            raw, st = safe_read(path, d.MAX_JSON_BYTES)
            if raw:
                try:
                    manifest = d.safe_json_parse(raw)
                    if not isinstance(manifest, dict):
                        continue
                except (ValueError, json.JSONDecodeError):
                    incomplete = True
                    continue
                self.baseline["native_hosts"].append(d.digest(str(path) + ":" + d.digest(raw)))
                host_path = str(manifest.get("path", ""))
                if host_path and (d.is_temp_executable(host_path) or host_path.startswith(self.home.as_posix())):
                    self.finding("NATIVE_HOST_OUTSIDE_STANDARD_PATH", "medium", "Browser native messaging host points into temporary or user location", path,
                                 {"host_path_id": d.digest(host_path)}, kind="EXPOSURE", attack="T1176.001")
            elif st != "ABSENT":
                incomplete = True
        policies = [Path("/etc/opt/chrome/policies/managed"), Path("/etc/chromium/policies/managed"),
                    Path("/etc/brave/policies/managed"), Path("/etc/opt/edge/policies/managed"),
                    Path("/etc/firefox/policies"), Path("/usr/lib/firefox/distribution")]
        policy_files, trunc = self._files(policies, extensions={".json"}, limit=200)
        incomplete |= trunc
        for p in policy_files:
            raw, st = safe_read(p, d.MAX_JSON_BYTES)
            if raw:
                try:
                    obj = d.safe_json_parse(raw)
                except (ValueError, json.JSONDecodeError):
                    incomplete = True
                    continue
                if isinstance(obj, dict):
                    forced = any(k in obj for k in ("ExtensionInstallForcelist", "ExtensionInstallSources", "ExtensionSettings", "DisableAppUpdate"))
                    if forced:
                        self.finding("BROWSER_ENTERPRISE_POLICY", "low", "Browser management policy requires authorization review", p,
                                     {"force_install_policy_detected": forced}, kind="EXPOSURE")
            elif st != "ABSENT":
                incomplete = True
        self.stats["browsers"] = {"profiles": stats, "native_hosts_count": len(natives),
                                   "enterprise_policy_files_count": len(policy_files)}
        self.checked("browsers", "PARTIAL" if incomplete else "COMPLETED",
                     "Static browser extensions, Firefox add-on permission metadata, native messaging hosts, managed policies; no cookies/passwords/history collected",
                     sum(x.get("extensions", 0) for x in stats.values()) + len(natives) + len(policy_files))

    def auth(self) -> None:
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S UTC")
        event_limit = self.profile_config["journal_lines"]
        r = self.command("journalctl", ["--since", since, "--lines", str(event_limit), "--no-pager", "--output=json",
                                       "--output-fields=MESSAGE,_SYSTEMD_UNIT,_COMM,__REALTIME_TIMESTAMP"], timeout=24)
        if r["status"] not in ("COMPLETED", "PARTIAL"):
            self.checked("auth", r["status"], "No usable journald data; cannot infer absence of intrusion")
            return
        counters: Counter[str] = Counter()
        lines = 0
        malformed = 0
        within_incident_window = Counter()
        timestamp_errors = 0
        for line in r["stdout"].splitlines():
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
                            within_incident_window.update(signals)
                    except (ValueError, TypeError, OverflowError, KeyError):
                        timestamp_errors += 1
            except (ValueError, TypeError, json.JSONDecodeError):
                malformed += 1
        if counters["SSH_ACCEPTED"]:
            self.finding("REMOTE_AUTHENTICATION_REVIEW", "low", "SSH logins observed; compare timestamps and source against your own sessions", "journald://ssh",
                         {"ssh_accepted_count": counters["SSH_ACCEPTED"]}, kind="CONTEXT", attack="T1078")
        self.stats["auth"] = {"events_examined": lines, "event_counts": dict(counters), "malformed": malformed,
                              "invalid_incident_timestamps": timestamp_errors,
                              "window_days_max": 30, "max_event_lines": event_limit,
                              "event_counts_0_to_72h_after_incident": dict(within_incident_window) if self.incident_at else None}
        partial = r["status"] != "COMPLETED" or lines == 0 or malformed > 0 or timestamp_errors > 0 or lines >= event_limit
        self.checked("auth", "PARTIAL" if partial else "COMPLETED",
                     "Most recent bounded journald entries within 30 days; no raw messages retained; absence of logging is not absence of incident", lines)

    def packages(self) -> None:
        installed = {}
        names = ("openssh-server", "anydesk", "rustdesk", "teamviewer", "x11vnc", "tigervnc-standalone-server",
                 "chrome-remote-desktop", "clamav", "auditd", "apparmor", "ufw", "firefox", "google-chrome-stable", "brave-browser")
        for name in names:
            # dpkg-query is not used: direct passive check of dpkg metadata only.
            raw, st = safe_read(Path("/var/lib/dpkg/info") / f"{name}.list", 128*1024)
            if raw:
                installed[name] = True
        self.stats["packages"] = {"selected_package_filelists_present": sorted(installed)}
        repos, trunc = self._files([Path("/etc/apt/sources.list.d")], extensions={".list", ".sources"}, limit=150)
        repos.append(Path("/etc/apt/sources.list"))
        insecure_repo_files = 0
        for p in repos:
            raw, st = safe_read(p, 128 * 1024)
            if raw:
                content = raw.decode("utf-8", "replace")
                if re.search(r"\btrusted\s*=\s*yes\b|\bAllow-Insecure:\s*yes\b", content, re.I):
                    insecure_repo_files += 1
                    self.finding("INSECURE_APT_REPOSITORY_SETTING", "medium", "APT source disables trust checks", p,
                                 {"insecure_auth_override": True}, kind="HARDENING")
        if self.profile == "deep":
            verify = self.command("dpkg", ["--verify"], timeout=110, limit=2*1024*1024)
            if verify["status"] in ("COMPLETED", "PARTIAL") or (verify["exit"] in (1, 2) and bool(verify["stdout"])):
                affected = [line for line in verify["stdout"].splitlines() if line.strip()]
                self.stats["package_integrity"] = {"changed_file_records": len(affected), "unverified_after_cap": verify["truncated"], "command_exit": verify["exit"]}
                if affected:
                    self.finding("DPKG_FILE_DRIFT", "low", "Installed files differ from package metadata; config changes can be legitimate",
                                 "dpkg://verify", {"record_count": len(affected)}, kind="CONTEXT")
            else:
                self.stats["package_integrity"] = {"status": verify["status"], "error": verify["error"]}
            status = "PARTIAL" if verify["status"] != "COMPLETED" or trunc or self.scope != "system" else "COMPLETED"
            detail = "APT source policy + dpkg --verify (unprivileged results limited). Drift is not malware attribution; tracked package content only"
        else:
            status = "PARTIAL"
            detail = "APT source policy and selected package metadata only; complete dpkg integrity check requires --scope system --profile deep"
        self.stats["repos"] = {"source_files_checked": len(repos), "insecure_source_files": insecure_repo_files}
        self.checked("packages", status, detail, len(repos))

    def kernel(self) -> None:
        stats: dict[str, Any] = {}
        for name, path in (("taint", "/proc/sys/kernel/tainted"), ("modules", "/proc/modules"),
                           ("lsm", "/sys/kernel/security/lsm")):
            raw, st = safe_read(Path(path), 256*1024 if name == "modules" else 4096)
            if raw is None:
                stats[name + "_status"] = st
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
        if self.scope == "system":
            mok = self.command("mokutil", ["--sb-state"], timeout=7)
            stats["secure_boot_status"] = "UNKNOWN" if mok["status"] != "COMPLETED" else (
                "ENABLED" if "SecureBoot enabled" in mok["stdout"] else "DISABLED_OR_UNSUPPORTED")
        self.stats["kernel"] = stats
        self.checked("kernel", "PARTIAL", "Kernel taint/modules/AppArmor/Secure Boot signals only. Cannot rule out kernel/rootkit/firmware compromise")
