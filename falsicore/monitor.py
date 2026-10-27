"""Opt-in local systemd user timer. Scans remain passive; enabling a timer is explicit configuration change."""
from __future__ import annotations

import os
from pathlib import Path

from .safety import exclusive_write, run_command

TIMER_NAME = "falsicore-user.timer"
SERVICE_NAME = "falsicore-user.service"
MARKER = "# FALSICORE 0.1 managed user timer: optional, no uploads, no root escalation"


def _escape_systemd_argument(value: str) -> str:
    if any(ch in value for ch in ("\x00", "\r", "\n", "%")):
        raise ValueError("Unsupported source path for systemd unit; percent/newline/NUL forbidden")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unit_contents(bundle: Path) -> tuple[str, str]:
    bundle = bundle.absolute()
    runner = bundle / "run.sh"
    if runner.is_symlink() or not runner.is_file() or bundle.is_symlink():
        raise ValueError("Refusing to schedule missing or symlinked run.sh")
    script = _escape_systemd_argument(str(runner))
    base = _escape_systemd_argument(str(bundle))
    service = f"""{MARKER}
[Unit]
Description=FALSICORE passive user-level security scan

[Service]
Type=oneshot
WorkingDirectory={base}
ExecStart=/usr/bin/bash {script} --profile standard
NoNewPrivileges=true
UMask=0077
"""
    timer = f"""{MARKER}
[Unit]
Description=Daily offline FALSICORE scan, opt-in only

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
Unit={SERVICE_NAME}

[Install]
WantedBy=timers.target
"""
    return service, timer


def _get_paths(home: Path) -> tuple[Path, Path]:
    directory = home / ".config" / "systemd" / "user"
    ancestor = directory.absolute()
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise PermissionError("Symlink in user service directory path")
        ancestor = ancestor.parent
    return directory / SERVICE_NAME, directory / TIMER_NAME


def enable(bundle: Path, home: Path) -> str:
    if os.geteuid() == 0:
        raise PermissionError("Use a normal desktop account, never root")
    service_content, timer_content = unit_contents(bundle)
    service_path, timer_path = _get_paths(home)
    service_path.parent.mkdir(parents=True, exist_ok=True)
    for path, expected in ((service_path, service_content), (timer_path, timer_content)):
        if path.is_symlink():
            raise PermissionError("Refusing symlinked systemd unit")
        if path.exists() and (path.stat().st_uid != os.geteuid() or path.read_text(encoding="utf-8") != expected):
            raise FileExistsError(f"Refusing to replace an edited or unrelated service: {path.name}")
    for path, expected in ((service_path, service_content), (timer_path, timer_content)):
        if not path.exists():
            exclusive_write(path, expected)
    for args in (("--user", "daemon-reload"), ("--user", "enable", "--now", TIMER_NAME)):
        r = run_command("systemctl", list(args), timeout=20, limit=32_768)
        if r["status"] != "COMPLETED":
            raise RuntimeError(f"systemctl {' '.join(args[1:])} failed: {r['status']}; saved units require manual review")
    return "User-level daily timer ENABLED at 03:00 UTC; no network telemetry, no sudo, no destructive remediation."


def disable(bundle: Path, home: Path) -> str:
    if os.geteuid() == 0:
        raise PermissionError("Use a normal desktop account, never root")
    service_content, timer_content = unit_contents(bundle)
    service_path, timer_path = _get_paths(home)
    for path, expected in ((service_path, service_content), (timer_path, timer_content)):
        if path.is_symlink() or (path.exists() and path.read_text(encoding="utf-8") != expected):
            raise PermissionError(f"Timer config changed; refusing to remove {path.name}")
    response = run_command("systemctl", ["--user", "disable", "--now", TIMER_NAME], timeout=20)
    if response["status"] != "COMPLETED":
        raise RuntimeError("Unable to disable timer; user systemd instance might be unavailable")
    for path in (service_path, timer_path):
        if path.exists():
            path.unlink()
    run_command("systemctl", ["--user", "daemon-reload"], timeout=20)
    return "User-level timer DISABLED. Previous forensic reports preserved."


def status() -> str:
    r = run_command("systemctl", ["--user", "is-enabled", TIMER_NAME], timeout=12, limit=2048)
    return "user systemd timer status: " + (r["stdout"].strip() or r["status"])
