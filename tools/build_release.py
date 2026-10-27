#!/usr/bin/env python3
"""Deterministic source-manifest and ZIP packager; run from the project root."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git", ".venv", ".tox"}
IGNORED_FILES = {".coverage", "SOURCE_MANIFEST.sha256", ".DS_Store"}
ROOT_ALLOW = {
    ".gitignore", ".gitattributes", "README.md", "SECURITY.md", "CONTRIBUTING.md",
    "CHANGELOG.md", "Makefile", "run.sh", "falsicore.py", "pyproject.toml",
    "LICENSE", "LICENSE.md",
}
SOURCE_DIRS = {"falsicore", "tests", "tools"}
DOCS_DIR = "docs"
WORKFLOW_FILES = {
    ".github/workflows/verify.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/release.yml",
    ".github/dependabot.yml",
}


def allowed_release_path(relative: Path) -> bool:
    parts = relative.parts
    if len(parts) == 1:
        return parts[0] in ROOT_ALLOW
    if len(parts) == 2 and parts[0] in SOURCE_DIRS:
        return relative.suffix == ".py"
    if len(parts) == 2 and parts[0] == DOCS_DIR:
        return relative.suffix in (".md", ".json")
    return relative.as_posix() in WORKFLOW_FILES
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def source_files() -> list[Path]:
    gathered = []
    for path in ROOT.rglob("*"):
        if any(chunk in IGNORED_DIRS for chunk in path.relative_to(ROOT).parts):
            continue
        if path.name in IGNORED_FILES:
            continue
        # Check symlinks before is_dir(): a symlink to a directory reports
        # is_dir() == True and would otherwise escape our fail-closed gate.
        if path.is_symlink():
            raise ValueError("Symlink source forbidden: " + str(path))
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Nonregular source forbidden: " + str(path))
        relative = path.relative_to(ROOT)
        if not allowed_release_path(relative):
            raise ValueError("Unexpected release payload; move private/generated files outside project: " + relative.as_posix())
        gathered.append(path)
    return sorted(gathered, key=lambda p: p.relative_to(ROOT).as_posix())


def _read_safe_source(path: Path, size_cap: int = 4 * 1024 * 1024) -> bytes:
    """Read regular source bytes once with no symlink traversal in any ancestor."""
    absolute = path.absolute()
    parts = absolute.parts[1:]
    if not parts or len(parts) > 64 or any(p in ("", ".", "..") for p in parts):
        raise ValueError("Unsafe release source path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", directory_flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        source_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            metadata = os.fstat(source_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > size_cap:
                raise ValueError("Release requires bounded regular files")
            chunks = bytearray()
            while len(chunks) <= size_cap:
                chunk = os.read(source_fd, min(65536, size_cap + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) > size_cap:
                raise ValueError("Release source too large")
            return bytes(chunks)
        finally:
            os.close(source_fd)
    finally:
        os.close(fd)


def build(destination: Path) -> tuple[str, int]:
    if destination.is_symlink():
        raise ValueError("Release output cannot be a symlink")
    if destination.exists():
        raise FileExistsError("Release destination already exists")
    if destination.absolute().is_relative_to(ROOT):
        raise ValueError("Release output must be outside the source tree")
    files = source_files()
    # Read each file exactly once. The manifest and archive therefore commit to
    # identical snapshots, even if a developer edits a file during packaging.
    sources = {p.relative_to(ROOT).as_posix(): _read_safe_source(p) for p in files}
    entries = [f"{hashlib.sha256(content).hexdigest()}  {name}" for name, content in sorted(sources.items())]
    manifest_bytes = ("\n".join(entries) + "\n").encode("utf-8")
    sources["SOURCE_MANIFEST.sha256"] = manifest_bytes

    # Manifest generation is intentional; ZIP creation is atomic so a failed
    # build cannot be mistaken for a complete distributable artifact.
    (ROOT / "SOURCE_MANIFEST.sha256").write_bytes(manifest_bytes)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".falsicore-", suffix=".zip.tmp",
                                         dir=destination.parent, delete=False) as stage:
            temp_path = Path(stage.name)
        with ZipFile(temp_path, "w", ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as bundle:
            for relative, content in sorted(sources.items()):
                info = ZipInfo(filename=ROOT.name + "/" + relative, date_time=FIXED_TIME)
                info.create_system = 3
                mode = 0o755 if Path(relative).name in ("run.sh", "falsicore.py", "build_release.py") else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = ZIP_DEFLATED
                info._compresslevel = 9
                bundle.writestr(info, content)
        with open(temp_path, "rb") as artifact:
            os.fsync(artifact.fileno())
        # An exclusive hard-link commit is atomic and fails if a file appears
        # at the destination between validation and commit (unlike os.replace).
        os.link(temp_path, destination, follow_symlinks=False)
        temp_path.unlink()
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    return digest, len(sources)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tools/build_release.py /path/to/release.zip")
    digest, count = build(Path(sys.argv[1]))
    print(f"sha256={digest} files={count}")
