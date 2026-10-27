"""Single-file distribution, integrity preflight and isolated self-tests.

Checksums detect inconsistent/corrupt content, not publisher authenticity.
Compare the separately published SHA-256 before executing this application.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .safety import run_test_suite

MANIFEST = "FALSICORE_BUNDLE.json"
MAX_MEMBERS = 160
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 20 * 1024 * 1024


def read_verified_bundle(path: Path) -> dict[str, bytes]:
    """Validate a bounded, regular-file-only bundle before using its payload."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("Application must be a regular file, not a symlink")
    if path.stat().st_size > MAX_TOTAL:
        raise ValueError("Application size limit exceeded")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > MAX_MEMBERS or len(names) != len(set(names)):
            raise ValueError("Duplicate members or excessive bundle size")
        if MANIFEST not in names:
            raise ValueError("Bundle manifest missing")
        if sum(e.file_size for e in entries) > MAX_TOTAL:
            raise ValueError("Expanded bundle size limit exceeded")
        for entry in entries:
            p = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (p.is_absolute() or any(x in {".", "..", ""} for x in entry.filename.split("/"))
                    or "\\" in entry.filename or any(ord(c) < 32 for c in entry.filename)
                    or entry.is_dir() or stat.S_ISLNK(mode)
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                    or entry.file_size > MAX_MEMBER):
                raise ValueError("Unsafe bundle member")
        manifest = json.loads(archive.read(MANIFEST))
        if not isinstance(manifest, dict) or manifest.get("schema") != "falsicore.bundle.v1":
            raise ValueError("Unsupported bundle manifest")
        expected = manifest.get("sha256")
        if not isinstance(expected, dict) or set(expected) != set(names) - {MANIFEST}:
            raise ValueError("Bundle members do not match manifest")
        result: dict[str, bytes] = {}
        for name in sorted(expected):
            raw = archive.read(name)
            digest = expected[name]
            if (not isinstance(digest, str) or len(digest) != 64
                    or hashlib.sha256(raw).hexdigest() != digest):
                raise ValueError("Bundle member checksum mismatch")
            result[name] = raw
    return result


def export_source(payload: dict[str, bytes], destination: Path) -> Path:
    """Create a new private source tree; never overwrite a previous checkout."""
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Source destination already exists; nothing overwritten")
    ancestor = destination.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise PermissionError("Symlinked export parent refused")
        ancestor = ancestor.parent
    parent = destination.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise PermissionError("Export parent must be owned by this user and not group/world writable")
    destination.mkdir(mode=0o700)
    for name, raw in sorted(payload.items()):
        if name == "__main__.py":
            continue  # zipapp-only entry point, not part of the source manifest
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe source member")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o700 if target.name in {"run.sh", "falsicore.py"} else 0o600)
    return destination


def self_test(payload: dict[str, bytes]) -> int:
    """Run the embedded full unittest suite in an ephemeral source checkout."""
    with tempfile.TemporaryDirectory(prefix="falsicore-selftest-") as folder:
        checkout = export_source(payload, Path(folder) / "source")
        result = run_test_suite(checkout)
        print(result["stdout"])
        return 0 if result["status"] == "COMPLETED" else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        payload = read_verified_bundle(Path(sys.argv[0]).absolute())
        if args == ["self-test"]:
            return self_test(payload)
        if args == ["verify-app"]:
            print("VERIFIED: bundle file set and member SHA-256 checksums")
            print("Not a digital signature or host security attestation.")
            return 0
        if args[:1] == ["export-source"]:
            if len(args) != 2:
                raise ValueError("Usage: falsicore.pyz export-source NEW_DIRECTORY")
            path = export_source(payload, Path(args[1]))
            print("SOURCE EXPORTED:", path)
            return 0
        if args[:1] == ["monitor"]:
            # A timer must not point at a movable Downloads file. Export source
            # first, then use the explicit opt-in source CLI timer workflow.
            raise ValueError("Scheduling is not enabled from a portable file. Export source and use its opt-in monitor command.")
        if args in (["--help"], ["-h"]):
            print("Portable commands: verify-app | self-test | export-source NEW_DIRECTORY")
        from .cli import main as cli_main
        return cli_main(args or ["scan", "--scope", "user", "--auto-compare"])
    except KeyboardInterrupt:
        print("Скасовано. Незавершений звіт не є результатом перевірки.", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print("FALSICORE ERROR:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2
