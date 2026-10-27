#!/usr/bin/env python3
"""Build the ONE full local distribution ZIP, deterministically.

Layout (prefix falsicore-<version>-full/):
  falsicore.pyz        portable application, byte-identical to tools/build_app.py
  run.sh               launcher that refuses a pyz whose SHA-256 differs
  START_HERE_UA.md     operator instructions (docs/OPERATOR_UA.md)
  source/...           allowlisted repository tree incl. SOURCE_MANIFEST.sha256
  verification/...     optional sanitized evidence (*.md, *.json, *.txt) from --evidence
  SHA256SUMS           hashes of every other member (never of itself)

The ZIP's own hash is written NEXT TO it (<zip>.sha256), never inside it.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build_app
from tools import build_release as source

EVIDENCE_SUFFIXES = {".md", ".json", ".txt"}
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024

LAUNCHER = """#!/usr/bin/env bash
# Full-package launcher: verifies the application hash, then runs it as the
# current user. No install, no network, no automatic sudo.
set -euo pipefail
cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")"
if [[ "$(id -u)" -eq 0 ]]; then
  printf 'Run ./run.sh as your regular user; a system scan is an explicit separate command.\\n' >&2
  exit 2
fi
command -v sha256sum >/dev/null || {{ printf 'sha256sum is required.\\n' >&2; exit 2; }}
if ! printf '%s  %s\\n' '{digest}' 'falsicore.pyz' | sha256sum --status -c -; then
  printf 'Application checksum mismatch. Nothing executed.\\n' >&2
  exit 2
fi
exec /usr/bin/python3 -I ./falsicore.pyz "$@"
"""


def _member(name: str, mode: int) -> ZipInfo:
    info = ZipInfo(name, date_time=source.FIXED_TIME)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = ZIP_DEFLATED
    info._compresslevel = 9
    return info


def _evidence(folder: Path | None) -> dict[str, bytes]:
    """Sanitized evidence files only: flat folder, allowlisted suffixes, bounded size."""
    if folder is None:
        return {}
    out: dict[str, bytes] = {}
    for path in sorted(folder.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Evidence must be regular files: {path.name}")
        if path.suffix not in EVIDENCE_SUFFIXES:
            raise ValueError(f"Evidence type not allowed in release: {path.name}")
        data = source._read_safe_source(path, MAX_EVIDENCE_BYTES)
        if b"/home/" in data or b"/root/" in data:
            raise ValueError(f"Evidence looks unsanitized (contains a home path): {path.name}")
        out["verification/" + path.name] = data
    return out


def payload(evidence: Path | None = None) -> tuple[dict[str, tuple[bytes, int]], str]:
    sources = {p.relative_to(source.ROOT).as_posix(): source._read_safe_source(p) for p in source.source_files()}
    manifest = source.manifest_for(sources)
    if manifest != (source.ROOT / "SOURCE_MANIFEST.sha256").read_bytes():
        raise ValueError("SOURCE_MANIFEST.sha256 is stale; run tools/build_release.py --write-manifest")
    pyz = build_app.bundle_bytes(sources)
    digest = hashlib.sha256(pyz).hexdigest()
    members: dict[str, tuple[bytes, int]] = {
        "falsicore.pyz": (pyz, 0o644),
        "run.sh": (LAUNCHER.format(digest=digest).encode(), 0o755),
        "START_HERE_UA.md": (sources["docs/OPERATOR_UA.md"], 0o644),
        "source/SOURCE_MANIFEST.sha256": (manifest, 0o644),
    }
    for name, raw in sources.items():
        executable = Path(name).name in ("run.sh", "falsicore.py")
        members["source/" + name] = (raw, 0o755 if executable else 0o644)
    for name, raw in _evidence(evidence).items():
        members[name] = (raw, 0o644)
    sums = "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, (raw, _) in sorted(members.items()))
    members["SHA256SUMS"] = (sums.encode(), 0o644)
    return members, digest


def build(out_dir: Path, evidence: Path | None = None) -> dict:
    out_dir = out_dir.absolute()
    if out_dir.is_relative_to(source.ROOT):
        raise ValueError("Output must be outside the source tree")
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    version = source.version()
    prefix = f"falsicore-{version}-full/"
    zip_path = out_dir / f"falsicore-{version}-full.zip"
    members, pyz_digest = payload(evidence)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, (raw, mode) in sorted(members.items()):
            bundle.writestr(_member(prefix + name, mode), raw)
    data = buffer.getvalue()
    with zip_path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    zip_digest = hashlib.sha256(data).hexdigest()
    # Whole-artifact hash lives outside the artifact it describes.
    (out_dir / (zip_path.name + ".sha256")).write_text(f"{zip_digest}  {zip_path.name}\n")
    return {"zip": str(zip_path), "zip_sha256": zip_digest, "pyz_sha256": pyz_digest,
            "members": len(members), "bytes": len(data)}


if __name__ == "__main__":
    args = sys.argv[1:]
    evidence_dir = None
    if len(args) == 3 and args[1] == "--evidence":
        evidence_dir = Path(args[2])
        args = args[:1]
    if len(args) != 1:
        raise SystemExit("Usage: python3 tools/build_full.py OUT_DIR [--evidence SANITIZED_DIR]")
    result = build(Path(args[0]), evidence_dir)
    print(" ".join(f"{k}={v}" for k, v in result.items()))
