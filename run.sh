#!/usr/bin/env bash
# Single command: source integrity preflight, bounded passive scan, manifest verification, readable HTML.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(id -u)" -eq 0 ]]; then
  printf 'Run ./run.sh as your regular Ubuntu user; root requires explicit CLI scope.\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null; then
  printf 'sha256sum missing; source integrity preflight cannot run.\n' >&2
  exit 2
fi
if ! sha256sum --status -c SOURCE_MANIFEST.sha256; then
  printf 'Source integrity preflight FAILED. Do not execute a modified bundle.\n' >&2
  exit 2
fi
exec /usr/bin/python3 -I falsicore.py scan --scope user --auto-compare "$@"
