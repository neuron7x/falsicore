#!/usr/bin/env python3
"""Build a deterministic self-contained Python application, without pip."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

# A script invocation from tools/ does not place the project root on sys.path.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import build_release as source

ENTRY = b'''"""Portable FALSICORE entry point (Python 3.10+, Linux)."""
import sys
sys.dont_write_bytecode = True
if sys.version_info < (3, 10) or not sys.platform.startswith("linux"):
    raise SystemExit("FALSICORE requires Linux and Python 3.10 or newer")
from falsicore.bundle import main
raise SystemExit(main())
'''


def bundle_bytes(payload: dict[str, bytes]) -> bytes:
    members = dict(payload)
    entries = [hashlib.sha256(raw).hexdigest() + "  " + name for name, raw in sorted(members.items())]
    members["SOURCE_MANIFEST.sha256"] = ("\n".join(entries) + "\n").encode()
    members["__main__.py"] = ENTRY
    manifest = {"schema": "falsicore.bundle.v1", "sha256": {
        name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(members.items())}}
    members["FALSICORE_BUNDLE.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, raw in sorted(members.items()):
            item = ZipInfo(name, date_time=source.FIXED_TIME)
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | 0o600) << 16
            item.compress_type = ZIP_DEFLATED
            item._compresslevel = 9
            bundle.writestr(item, raw)
    return buffer.getvalue()


def build(destination: Path) -> str:
    if destination.absolute().is_relative_to(source.ROOT):
        raise ValueError("Build outside the source tree")
    payload = {p.relative_to(source.ROOT).as_posix(): source._read_safe_source(p) for p in source.source_files()}
    data = bundle_bytes(payload)
    with destination.open("xb") as result:
        result.write(data)
        result.flush()
        os.fsync(result.fileno())
    # Source checkout and portable export have the same exact manifest.
    with ZipFile(io.BytesIO(data)) as archive:
        (source.ROOT / "SOURCE_MANIFEST.sha256").write_bytes(archive.read("SOURCE_MANIFEST.sha256"))
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tools/build_app.py /outside/source/falsicore.pyz")
    print(build(Path(sys.argv[1])))
