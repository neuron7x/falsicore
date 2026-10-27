"""No-shell command executor, local private artifact handling, command audit metadata."""
from __future__ import annotations

import datetime as dt
import errno
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MAX_COMMAND_OUTPUT = 32 * 1024 * 1024
MAX_DIAGNOSTIC_OUTPUT = 64 * 1024
TRUSTED_BIN_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
COMMAND_ALLOWLIST = {
    "uname", "ss", "ip", "journalctl", "systemctl", "dpkg", "ufw",
    "mokutil", "aa-status", "crontab", "getent", "lsmod", "findmnt",
    "timedatectl", "sysctl", "snap", "flatpak", "loginctl",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def checked_executable(name: str) -> str | None:
    if name not in COMMAND_ALLOWLIST:
        raise ValueError(f"Disallowed executable: {name}")
    for base in TRUSTED_BIN_DIRS:
        binary = Path(base) / name
        if binary.is_file() and os.access(binary, os.X_OK):
            return str(binary)
    return None


def minimal_env() -> dict[str, str]:
    env = {"PATH": ":".join(TRUSTED_BIN_DIRS), "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
    # DBUS_SESSION_BUS_ADDRESS is not needed for our current commands and may be attacker-controlled.
    return env


def run_command(name: str, args: list[str], timeout: float = 12.0, limit: int = MAX_COMMAND_OUTPUT,
                env: dict[str, str] | None = None) -> dict:
    """Capture a bounded subprocess tree without shell expansion.

    Success requires BOTH the direct child to exit with zero and the output
    pipe to reach EOF. EOF alone is not process completion; a child exiting
    alone is not EOF when its descendants inherited that pipe. On deadline,
    truncation or I/O failure, kill the dedicated process group.
    """
    binary = checked_executable(name)
    if binary is None:
        return {"status": "UNAVAILABLE", "stdout": "", "stderr": "", "exit": None, "elapsed_ms": 0,
                "truncated": False, "error": "binary missing", "residual_killed": False}
    return _run_bounded(binary, args, timeout, limit, env=env)


def _leader_exit(pid: int) -> int | None:
    """Exit code of the group leader WITHOUT reaping it.

    A zombie leader keeps its PID, and therefore its process-group ID, reserved.
    Reaping only after the final killpg() guarantees the signal cannot reach a
    foreign group that reused the number.
    """
    try:
        info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return None
    if info is None or info.si_pid == 0:
        return None
    if info.si_code == os.CLD_EXITED:
        return info.si_status
    return -info.si_status


def _run_bounded(binary: str, args: list[str], timeout: float, limit: int,
                 merge_stderr: bool = False, env: dict[str, str] | None = None) -> dict:
    """Internal executor; system probes use the allowlist in run_command.

    stdout is the parsed channel and is bounded by `limit`; overflow is PARTIAL
    and kills the group. stderr is diagnostics only, bounded separately and never
    parsed as data unless `merge_stderr` is requested (self-test transcript).
    """
    if any(not isinstance(a, str) or "\x00" in a for a in args):
        raise ValueError("Invalid command argument")
    if timeout <= 0 or timeout > 180 or limit < 0 or limit > MAX_COMMAND_OUTPUT:
        raise ValueError("Command timeout or output bounds invalid")

    started = time.monotonic()
    deadline = started + timeout
    proc: subprocess.Popen | None = None
    captured = bytearray()
    diagnostics = bytearray()
    status, error, truncated, exit_code = "FAILED", "", False, None
    residual_killed = False
    selector = selectors.DefaultSelector()
    must_kill = False
    try:
        proc = subprocess.Popen(
            [binary, *args], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            stdin=subprocess.DEVNULL, env=env if env is not None else minimal_env(), shell=False,
            start_new_session=True, close_fds=True,
        )
        streams = [s for s in (proc.stdout, proc.stderr) if s is not None]
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error, must_kill = "timeout", True
                break
            leader = _leader_exit(proc.pid)
            # There may be no open pipe even though the child is still running.
            # Do not label that condition successful.
            if not selector.get_map():
                if leader is not None:
                    exit_code = leader
                    break
                time.sleep(min(remaining, 0.02))
                continue

            events = selector.select(timeout=min(remaining, 0.05))
            for key, _ in events:
                is_stdout = key.fileobj is proc.stdout
                budget = limit + 1 - len(captured) if is_stdout else 65536
                try:
                    chunk = os.read(key.fd, min(65536, max(1, budget)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if not is_stdout:
                    if len(diagnostics) < MAX_DIAGNOSTIC_OUTPUT:
                        diagnostics.extend(chunk[:MAX_DIAGNOSTIC_OUTPUT - len(diagnostics)])
                    continue
                captured.extend(chunk)
                if len(captured) > limit:
                    captured = captured[:limit]
                    status, error, truncated, must_kill = "PARTIAL", "output limit exceeded", True, True
                    break
            if must_kill:
                break
            if not selector.get_map():
                leader = _leader_exit(proc.pid)
                if leader is not None:
                    exit_code = leader
                    break

        if not must_kill:
            status = "COMPLETED" if exit_code == 0 else "FAILED"
            if exit_code is not None and exit_code < 0:
                error = "signal:" + _signal_name(-exit_code)
        else:
            status = "PARTIAL" if truncated else "FAILED"
    except (OSError, subprocess.SubprocessError) as exc:
        status, error, must_kill = "FAILED", type(exc).__name__, True
    except (KeyboardInterrupt, SystemExit):
        # Ctrl-C must not orphan a long-running probe in its separate session.
        must_kill = True
        raise
    finally:
        if proc is not None:
            # The leader is not reaped yet, so the group ID is still ours. Any
            # member still alive (a daemonized grandchild after a successful
            # exit included) belongs to this probe and is killed.
            residual_killed = not must_kill and _group_has_live_members(proc.pid)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                error = error or "PROCESS_GROUP_CLEANUP_DENIED"
            try:
                reaped = proc.wait(timeout=2)
                if exit_code is None and not must_kill:
                    exit_code = reaped
                elif exit_code is None:
                    exit_code = reaped
            except subprocess.TimeoutExpired:
                error = error or "PROCESS_GROUP_REAP_TIMEOUT"
            if must_kill and selector.get_map():
                # A pipe holder that escaped the group (setsid) keeps the pipe
                # open after killpg. Report it instead of waiting for it.
                if not selector.select(timeout=0.2):
                    error = (error + ";" if error else "") + "PIPE_HOLDER_OUTSIDE_GROUP"
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
        selector.close()

    return {
        "status": status, "stdout": captured.decode("utf-8", "replace"),
        "stderr": diagnostics.decode("utf-8", "replace"),
        "exit": exit_code, "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "truncated": truncated, "error": error, "residual_killed": residual_killed,
    }


def _group_has_live_members(pgid: int) -> bool:
    """True if a non-zombie process other than the leader is in group `pgid`.

    A zombie leader also answers killpg(), so its success alone says nothing.
    """
    try:
        entries = os.scandir("/proc")
    except OSError:
        return False
    with entries:
        for entry in entries:
            if not entry.name.isdigit() or int(entry.name) == pgid:
                continue
            try:
                with open(f"/proc/{entry.name}/stat", "rb") as f:
                    fields = f.read(4096).rsplit(b")", 1)[1].split()
            except (OSError, IndexError):
                continue
            if len(fields) > 2 and fields[2] == str(pgid).encode() and fields[0] != b"Z":
                return True
    return False


def _signal_name(number: int) -> str:
    try:
        return signal.Signals(number).name
    except ValueError:
        return str(number)


def safe_read(path: Path, limit: int = 131_072) -> tuple[bytes | None, str]:
    """Open a bounded regular file using no-follow directory descriptors.

    Every ancestor is opened with O_DIRECTORY | O_NOFOLLOW. Unlike checking
    Path.is_symlink() and then opening by name, this closes the user-controlled
    ancestor-swap window. A live root-compromised kernel is NOT a trust anchor.
    """
    if not isinstance(limit, int) or limit < 0 or limit > 8 * 1024 * 1024:
        raise ValueError("Invalid file read bound")
    try:
        absolute = path.absolute()
        components = absolute.parts[1:]
        if not components or len(components) > 64 or any(x in ("", ".", "..") for x in components):
            return None, "INVALID_PATH"
        dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open("/", dir_flags)
        try:
            for component in components[:-1]:
                next_fd = os.open(component, dir_flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            file_fd = os.open(components[-1], file_flags, dir_fd=fd)
            try:
                info = os.fstat(file_fd)
                if not stat.S_ISREG(info.st_mode):
                    return None, "NOT_REGULAR"
                if info.st_size > limit:
                    return None, "TOO_LARGE"
                chunks = bytearray()
                # A single read() may legally return fewer bytes than requested.
                while len(chunks) <= limit:
                    data = os.read(file_fd, min(65536, limit + 1 - len(chunks)))
                    if not data:
                        break
                    chunks.extend(data)
                if len(chunks) > limit:
                    return None, "TOO_LARGE"
                return bytes(chunks), "COMPLETED"
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)
    except FileNotFoundError:
        return None, "ABSENT"
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return None, "SYMLINK_OR_NOT_DIRECTORY"
        return None, "FAILED"


def require_private_parent(directory: Path) -> None:
    """Create a private output base; reject symlinks/shared-existing directories."""
    ancestor = directory.absolute()
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise PermissionError("Output base has a symlinked component")
        ancestor = ancestor.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError("Output directory ownership mismatch")
    if info.st_mode & 0o077:
        raise PermissionError("Output base is not private (chmod 700 it first)")


def create_run_directory(parent: Path) -> Path:
    os.umask(0o077)
    require_private_parent(parent)
    if shutil.disk_usage(parent).free < 32 * 1024 * 1024:
        raise OSError("Less than 32 MiB of free space: refusing a new forensic run")
    run = Path(tempfile.mkdtemp(prefix="run-", dir=str(parent)))
    os.chmod(run, 0o700)
    return run


def exclusive_write(path: Path, content: str | bytes) -> None:
    if path.parent.is_symlink():
        raise PermissionError("Symlinked parent")
    payload = content.encode("utf-8") if isinstance(content, str) else content
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_json(path: Path, data: Any) -> None:
    exclusive_write(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def run_test_suite(checkout: Path) -> dict:
    """Explicit self-test only: fixed interpreter command on verified sources.

    Not callable through Audit.command; no arbitrary command string is accepted.
    The same bounded, process-group-cleaning executor is used as for probes.
    """
    program = (
        "import sys,unittest;sys.dont_write_bytecode=True;"
        "sys.path.insert(0,sys.argv[1]);"
        "suite=unittest.defaultTestLoader.discover(sys.argv[1]+'/tests');"
        "r=unittest.TextTestRunner(verbosity=1).run(suite);"
        "sys.exit(0 if r.wasSuccessful() else 1)"
    )
    return _run_bounded(sys.executable, ["-I", "-B", "-c", program, str(checkout)], 180, 1048576,
                        merge_stderr=True)
