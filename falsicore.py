#!/usr/bin/env python3
"""Isolated-mode launcher. Import only audited sibling package from this bundle."""
import sys
from pathlib import Path

# Keep the scan from generating .pyc files outside its dedicated private output directory.
sys.dont_write_bytecode = True
# -I deliberately removes the script's directory; re-add only the verified bundle directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from falsicore.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
